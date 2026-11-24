package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// controlServer is the loopback-only control API (build plan §6.3):
// GET /health, POST /reload (pull now), POST /restart-core. It never
// binds a non-loopback address: newControlServer refuses anything
// whose host is not 127.0.0.1 or ::1.
// Slice 8 adds POST /relay-config: the panel hands this agent a rendered
// realm config.toml (co-located relay+node) and the agent writes it and
// restarts realm (see relay.go).
type controlServer struct {
	addr  string
	sup   *supervisor
	sbSup *supervisor // sing-box supervisor (slice 5); nil = no sing-box
	// reload pulls a fresh config from the panel now.
	reload func() error
	// configVersion is the currently applied panel config version.
	configVersion func() int
	// applyRelay writes a panel-rendered realm config and restarts
	// realm (slice 8); nil = this node does not apply relay configs.
	applyRelay func([]byte) error
	srv        *http.Server
}

// newControlServer builds the control server. addr must be loopback.
// sbSup may be nil (Xray-only). applyRelay may be nil.
func newControlServer(addr string, sup *supervisor, sbSup *supervisor, reload func() error, configVersion func() int, applyRelay func([]byte) error) (*controlServer, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid control address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("control address %q is not loopback; refusing to bind", addr)
	}
	cs := &controlServer{addr: addr, sup: sup, sbSup: sbSup, reload: reload, configVersion: configVersion, applyRelay: applyRelay}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", cs.handleHealth)
	mux.HandleFunc("/reload", cs.handleReload)
	mux.HandleFunc("/restart-core", cs.handleRestartCore)
	mux.HandleFunc("/relay-config", cs.handleRelayConfig)
	cs.srv = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return cs, nil
}

// Start serves in the background and returns the bound address (the
// configured port may be 0); callers use Stop to shut it down.
func (c *controlServer) Start() (string, error) {
	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		return "", fmt.Errorf("listen control %s: %w", c.addr, err)
	}
	go func() {
		_ = c.srv.Serve(ln)
	}()
	return ln.Addr().String(), nil
}

// Stop shuts the control server down (best effort).
func (c *controlServer) Stop() {
	if c.srv != nil {
		_ = c.srv.Close()
	}
}

func writeControlJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// handleHealth GET /health: agent version, applied config version and
// both cores' supervisor status. Used by systemd / install self-checks.
func (c *controlServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	st := c.sup.Status()
	resp := map[string]any{
		"ok":              true,
		"version":         Version,
		"config_version":  c.configVersion(),
		"xray_running":    st.Running,
		"xray_pid":        st.PID,
		"xray_uptime":     st.UptimeSec,
		"xray_restarts":   st.Restarts,
		"xray_last_err":   st.LastErr,
		"singbox_version": SingboxVersion,
	}
	if c.sbSup != nil {
		sb := c.sbSup.Status()
		resp["singbox_running"] = sb.Running
		resp["singbox_pid"] = sb.PID
		resp["singbox_uptime"] = sb.UptimeSec
		resp["singbox_restarts"] = sb.Restarts
		resp["singbox_last_err"] = sb.LastErr
	} else {
		resp["singbox_running"] = false
		resp["singbox_pid"] = 0
		resp["singbox_uptime"] = 0
		resp["singbox_restarts"] = 0
		resp["singbox_last_err"] = ""
	}
	writeControlJSON(w, http.StatusOK, resp)
}

// handleReload POST /reload: pull the panel config now and apply it.
// A successful reload already ensures both cores are running (304 and
// SHA-identical applies both start them); the check below covers a
// reload func that applied nothing (e.g. the panel was unreachable
// on a previous cycle and the stub path skipped the apply).
func (c *controlServer) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if err := c.reload(); err != nil {
		writeControlJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if !c.sup.IsRunning() {
		if err := c.sup.Start(); err != nil {
			writeControlJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "reload ok but xray failed to start: " + err.Error()})
			return
		}
	}
	// sing-box is left alone here: the applier owns its state (it
	// only runs when it has inbounds), and a reload already applied.
	writeControlJSON(w, http.StatusOK, map[string]any{"ok": true, "config_version": c.configVersion()})
}

// handleRestartCore POST /restart-core: bounce one core
// (?core=xray|sing-box, default xray). When the core is not running
// there is nothing to bounce, so start it instead (0.1.2 returned
// "xray is not running" and left the node down).
func (c *controlServer) handleRestartCore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	core := strings.TrimSpace(r.URL.Query().Get("core"))
	if core == "" {
		core = "xray"
	}
	var sup *supervisor
	switch core {
	case "xray":
		sup = c.sup
	case "sing-box":
		if c.sbSup == nil {
			writeControlJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "sing-box is not configured on this node"})
			return
		}
		sup = c.sbSup
	default:
		writeControlJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "unknown core " + core})
		return
	}
	if !sup.IsRunning() {
		if err := sup.Start(); err != nil {
			writeControlJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	} else if err := sup.Restart(); err != nil {
		writeControlJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	st := sup.Status()
	writeControlJSON(w, http.StatusOK, map[string]any{
		"ok": true, "core": core, "running": st.Running, "pid": st.PID,
	})
}

// handleRelayConfig POST /relay-config (slice 8): the panel hands this
// agent a rendered realm config.toml (co-located relay+node); the agent
// validates it, writes it and restarts realm. Loopback only (the
// control server refuses non-loopback binds); the body is the full
// config text, not a path (the agent writes to its own configured path).
func (c *controlServer) handleRelayConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if c.applyRelay == nil {
		writeControlJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "relay apply not configured on this node"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		ConfigToml string `json:"config_toml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeControlJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式不对"})
		return
	}
	if strings.TrimSpace(req.ConfigToml) == "" {
		writeControlJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "config_toml 不能为空"})
		return
	}
	if err := c.applyRelay([]byte(req.ConfigToml)); err != nil {
		writeControlJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeControlJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// isLoopbackAddr reports whether addr's host is a loopback IP.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}
