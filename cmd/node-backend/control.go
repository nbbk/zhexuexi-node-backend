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
type controlServer struct {
	addr string
	sup  *supervisor
	// reload pulls a fresh config from the panel now.
	reload func() error
	// configVersion is the currently applied panel config version.
	configVersion func() int
	srv           *http.Server
}

// newControlServer builds the control server. addr must be loopback.
func newControlServer(addr string, sup *supervisor, reload func() error, configVersion func() int) (*controlServer, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid control address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("control address %q is not loopback; refusing to bind", addr)
	}
	cs := &controlServer{addr: addr, sup: sup, reload: reload, configVersion: configVersion}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", cs.handleHealth)
	mux.HandleFunc("/reload", cs.handleReload)
	mux.HandleFunc("/restart-core", cs.handleRestartCore)
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
// Xray supervisor status. Used by systemd / install self-checks.
func (c *controlServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	st := c.sup.Status()
	writeControlJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"version":        Version,
		"config_version": c.configVersion(),
		"xray_running":   st.Running,
		"xray_pid":       st.PID,
		"xray_uptime":    st.UptimeSec,
		"xray_restarts":  st.Restarts,
		"xray_last_err":  st.LastErr,
	})
}

// handleReload POST /reload: pull the panel config now and apply it.
// A successful reload already ensures Xray is running (304 and
// SHA-identical applies both start it); the check below covers a
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
	writeControlJSON(w, http.StatusOK, map[string]any{"ok": true, "config_version": c.configVersion()})
}

// handleRestartCore POST /restart-core: bounce the Xray child process.
// When Xray is not running there is nothing to bounce, so start it
// instead (0.1.2 returned "xray is not running" and left the node down).
func (c *controlServer) handleRestartCore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !c.sup.IsRunning() {
		if err := c.sup.Start(); err != nil {
			writeControlJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	} else if err := c.sup.Restart(); err != nil {
		writeControlJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	st := c.sup.Status()
	writeControlJSON(w, http.StatusOK, map[string]any{
		"ok": true, "xray_running": st.Running, "xray_pid": st.PID,
	})
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
