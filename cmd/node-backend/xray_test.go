package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testRealityDoc builds a panel config doc with the default trio
// (reality + xhttp + hy2) and two users, mirroring the panel's
// default-trio output.
func testRealityDoc() *nodeConfig {
	return &nodeConfig{
		OK: true, NodeID: 1, ConfigVersion: 2, ETag: `"v2"`,
		Inbounds: []configInbound{
			{
				InboundID: 1, InboundTag: "reality-443", Protocol: "vless",
				Transport: "reality", Security: "reality", Port: 443,
				SNI: "www.example.com", RealityPrivateKey: "KMI9fIon8C4SCjMV5lydfxlLmiV9aKEvhRi73M2uf38",
				RealityPublicKey: "xm78RQAFG3hTqdLalPrH_A0ZlicL7-BpoJ0vZmj9MmY",
				RealityShortID:   "a1b2c3d4", RealityDest: "www.example.com:443",
				RealityServerName: "www.example.com", RealityFingerprint: "chrome",
				Flow: "xtls-rprx-vision", Enabled: true,
			},
			{
				InboundID: 2, InboundTag: "xhttp-443", Protocol: "vless",
				Transport: "xhttp", Security: "reality", Port: 8443,
				SNI: "www.example.com", RealityPrivateKey: "KMI9fIon8C4SCjMV5lydfxlLmiV9aKEvhRi73M2uf38",
				RealityPublicKey: "xm78RQAFG3hTqdLalPrH_A0ZlicL7-BpoJ0vZmj9MmY",
				RealityShortID:   "e5f6a7b8", RealityDest: "www.example.com:443",
				RealityServerName: "www.example.com", RealityFingerprint: "chrome",
				Enabled: true,
			},
			{
				InboundID: 3, InboundTag: "hy2-443", Protocol: "hysteria2",
				Transport: "quic", Security: "tls", Port: 443,
				SNI: "node1.example.com", Domain: "node1.example.com", Enabled: true,
			},
		},
		Users: []configUser{
			{UserID: "subuser:su-1", Kind: "subuser", ID: "su-1", Name: "u1",
				Email: "u-sub-su-1@node", VLESSUUID: "11111111-2222-3333-4444-555555555555"},
			{UserID: "merged:ms-1", Kind: "merged", ID: "ms-1", Name: "u2",
				Email: "u-merged-ms-1@node", VLESSUUID: "22222222-3333-4444-5555-666666666666"},
		},
	}
}

// parsedXray is the rendered config decoded back to a generic map.
type parsedXray struct {
	m map[string]any
}

func parseXrayJSON(t *testing.T, data []byte) parsedXray {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("rendered config is not valid JSON: %v", err)
	}
	return parsedXray{m: m}
}

func (p parsedXray) inbounds(t *testing.T) []map[string]any {
	t.Helper()
	raw, ok := p.m["inbounds"].([]any)
	if !ok {
		t.Fatalf("inbounds missing: %v", p.m)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("inbound is not an object: %v", r)
		}
		out = append(out, m)
	}
	return out
}

func (p parsedXray) inboundByTag(t *testing.T, tag string) map[string]any {
	t.Helper()
	for _, in := range p.inbounds(t) {
		if in["tag"] == tag {
			return in
		}
	}
	t.Fatalf("inbound %q not rendered", tag)
	return nil
}

func strMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("not an object: %v", v)
	}
	return m
}

// TestRenderRealityInbound: the default trio renders api + reality +
// xhttp; hy2 is skipped (sing-box core, later slice). REALITY carries
// no minClientVer (0.1.2), and Vision flow on clients.
func TestRenderRealityInbound(t *testing.T) {
	data, sha, skipped, err := renderXrayConfig(testRealityDoc(), 10085)
	if err != nil {
		t.Fatalf("renderXrayConfig: %v", err)
	}
	if strings.Contains(string(data), "minClientVer") {
		t.Fatalf("rendered config must not contain minClientVer")
	}
	if sha == "" {
		t.Fatalf("empty config sha")
	}
	if len(skipped) != 1 || skipped[0] != "hy2-443" {
		t.Fatalf("skipped = %v, want [hy2-443]", skipped)
	}
	p := parseXrayJSON(t, data)
	ins := p.inbounds(t)
	if len(ins) != 3 {
		t.Fatalf("rendered %d inbounds, want 3 (api + reality + xhttp)", len(ins))
	}

	api := p.inboundByTag(t, "api")
	if api["protocol"] != "dokodemo-door" || api["port"] != float64(10085) || api["listen"] != "127.0.0.1" {
		t.Fatalf("api inbound wrong: %v", api)
	}

	reality := p.inboundByTag(t, "reality-443")
	if reality["protocol"] != "vless" || reality["port"] != float64(443) {
		t.Fatalf("reality inbound wrong: %v", reality)
	}
	ss := strMap(t, reality["streamSettings"])
	if ss["network"] != "tcp" || ss["security"] != "reality" {
		t.Fatalf("reality streamSettings wrong: %v", ss)
	}
	rs := strMap(t, ss["realitySettings"])
	if _, hasMin := rs["minClientVer"]; hasMin {
		t.Fatalf("reality must not render minClientVer, got %v", rs["minClientVer"])
	}
	if rs["dest"] != "www.example.com:443" {
		t.Fatalf("dest = %v, want www.example.com:443", rs["dest"])
	}
	names, _ := rs["serverNames"].([]any)
	if len(names) != 1 || names[0] != "www.example.com" {
		t.Fatalf("serverNames = %v, want [www.example.com]", rs["serverNames"])
	}
	shortIDs, _ := rs["shortIds"].([]any)
	if len(shortIDs) != 1 || shortIDs[0] != "a1b2c3d4" {
		t.Fatalf("shortIds = %v, want [a1b2c3d4]", rs["shortIds"])
	}
	clients, _ := strMap(t, reality["settings"])["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("reality clients = %d, want 2", len(clients))
	}
	c0 := strMap(t, clients[0])
	if c0["flow"] != "xtls-rprx-vision" || c0["email"] != "u-sub-su-1@node" ||
		c0["id"] != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("reality client wrong: %v", c0)
	}

	// XHTTP: same REALITY block, xhttp network, no flow on clients.
	xhttp := p.inboundByTag(t, "xhttp-443")
	if xhttp["port"] != float64(8443) {
		t.Fatalf("xhttp port wrong: %v", xhttp)
	}
	xss := strMap(t, xhttp["streamSettings"])
	if xss["network"] != "xhttp" || xss["security"] != "reality" {
		t.Fatalf("xhttp streamSettings wrong: %v", xss)
	}
	xrs := strMap(t, xss["realitySettings"])
	if _, hasMin := xrs["minClientVer"]; hasMin {
		t.Fatalf("xhttp must not render minClientVer, got %v", xrs["minClientVer"])
	}
	xclients, _ := strMap(t, xhttp["settings"])["clients"].([]any)
	if len(xclients) != 2 {
		t.Fatalf("xhttp clients = %d, want 2", len(xclients))
	}
	if _, hasFlow := strMap(t, xclients[0])["flow"]; hasFlow {
		t.Fatalf("xhttp client must not carry a flow")
	}

	// Policy: inbound + user stats on (metering reads these in slice 4).
	policy := strMap(t, p.m["policy"])
	system := strMap(t, policy["system"])
	if system["statsInboundUplink"] != true || system["statsInboundDownlink"] != true {
		t.Fatalf("policy.system stats off: %v", system)
	}
}

// TestRenderSkipsDisabledAndNonVLESS: disabled inbounds are not
// rendered; other protocols are skipped, not errors.
func TestRenderSkipsDisabledAndNonVLESS(t *testing.T) {
	doc := testRealityDoc()
	doc.Inbounds[0].Enabled = false
	doc.Inbounds = append(doc.Inbounds, configInbound{
		InboundID: 4, InboundTag: "trojan-443", Protocol: "trojan",
		Transport: "tcp", Security: "tls", Port: 444, Enabled: true,
	})
	data, _, skipped, err := renderXrayConfig(doc, 10085)
	if err != nil {
		t.Fatalf("renderXrayConfig: %v", err)
	}
	p := parseXrayJSON(t, data)
	for _, in := range p.inbounds(t) {
		if in["tag"] == "reality-443" || in["tag"] == "trojan-443" {
			t.Fatalf("inbound %v should not be rendered", in["tag"])
		}
	}
	want := map[string]bool{"hy2-443": true, "trojan-443": true}
	for _, s := range skipped {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Fatalf("skipped = %v, missing %v", skipped, want)
	}
}

// TestRenderErrors: port conflicts, missing REALITY key and TLS
// without certs are hard errors (nothing is applied).
func TestRenderErrors(t *testing.T) {
	// Two enabled Xray inbounds on the same TCP port.
	doc := testRealityDoc()
	doc.Inbounds = append(doc.Inbounds, configInbound{
		InboundID: 9, InboundTag: "reality-dup", Protocol: "vless",
		Transport: "reality", Security: "reality", Port: 443,
		SNI: "www.example.com", RealityPrivateKey: "KMI9fIon8C4SCjMV5lydfxlLmiV9aKEvhRi73M2uf38",
		RealityShortID: "ffffffff", Enabled: true,
	})
	if _, _, _, err := renderXrayConfig(doc, 10085); err == nil || !strings.Contains(err.Error(), "443") {
		t.Fatalf("port conflict should error with the port, got %v", err)
	}

	// REALITY inbound without a private key.
	doc = testRealityDoc()
	doc.Inbounds[0].RealityPrivateKey = ""
	if _, _, _, err := renderXrayConfig(doc, 10085); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("missing private key should error, got %v", err)
	}

	// TLS inbound without certs (slice 7 ships them).
	doc = testRealityDoc()
	doc.Inbounds = append(doc.Inbounds, configInbound{
		InboundID: 10, InboundTag: "tls-443", Protocol: "vless",
		Transport: "tcp", Security: "tls", Port: 8443,
		SNI: "node1.example.com", Flow: "xtls-rprx-vision", Enabled: true,
	})
	if _, _, _, err := renderXrayConfig(doc, 10085); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("TLS without certs should error, got %v", err)
	}

	// Bad API port.
	if _, _, _, err := renderXrayConfig(testRealityDoc(), 0); err == nil {
		t.Fatalf("api port 0 should error")
	}
}

// TestVlessClients: disabled users and users without a UUID are left
// out of the client list.
func TestVlessClients(t *testing.T) {
	users := []configUser{
		{UserID: "subuser:a", Email: "u-sub-a@node", VLESSUUID: "11111111-2222-3333-4444-555555555555"},
		{UserID: "subuser:b", Email: "u-sub-b@node", VLESSUUID: "22222222-3333-4444-5555-666666666666", Disabled: true},
		{UserID: "subuser:c", Email: "u-sub-c@node", VLESSUUID: ""},
	}
	clients := vlessClients(users)
	if len(clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(clients))
	}
	if clients[0]["id"] != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("wrong client kept: %v", clients[0])
	}
}

// TestValidateXrayConfig runs the real Xray binary (pinned 26.11.9)
// against the rendered config: `xray run -test` must pass, and a
// broken config must fail.
func TestValidateXrayConfig(t *testing.T) {
	xrayBin := os.Getenv("XRAY_BIN")
	if xrayBin == "" {
		xrayBin = filepath.Join(os.Getenv("HOME"), "workspace", "toolchains", "xray", "xray")
	}
	if _, err := os.Stat(xrayBin); err != nil {
		t.Skipf("no xray binary at %s", xrayBin)
	}
	data, _, _, err := renderXrayConfig(testRealityDoc(), 10085)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(good, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := validateXrayConfig(xrayBin, good); err != nil {
		t.Fatalf("real xray rejected the rendered config: %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"inbounds": [{"port": "not-a-port"}]}`), 0o600); err != nil {
		t.Fatalf("write bad config: %v", err)
	}
	if err := validateXrayConfig(xrayBin, bad); err == nil {
		t.Fatalf("broken config passed validation")
	}
	if err := validateXrayConfig(xrayBin, filepath.Join(dir, "missing.json")); err == nil {
		t.Fatalf("missing config file passed validation")
	}
}

// TestRenderListenFromConfig: the public inbound listen address comes
// from the panel config (variable principle 2026-11-23); empty means
// 0.0.0.0, an invalid value fails the render.
func TestRenderListenFromConfig(t *testing.T) {
	doc := testRealityDoc()
	doc.Inbounds[0].Listen = "203.0.113.1"
	data, _, _, err := renderXrayConfig(doc, 10085)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	p := parseXrayJSON(t, data)
	if got := p.inboundByTag(t, "reality-443")["listen"]; got != "203.0.113.1" {
		t.Fatalf("reality listen = %v, want 203.0.113.1 (the configured value)", got)
	}
	if got := p.inboundByTag(t, "xhttp-443")["listen"]; got != "0.0.0.0" {
		t.Fatalf("empty listen should render 0.0.0.0, got %v", got)
	}

	doc = testRealityDoc()
	doc.Inbounds[0].Listen = "not-an-ip"
	if _, _, _, err := renderXrayConfig(doc, 10085); err == nil {
		t.Fatalf("invalid listen address should fail the render")
	}
}

// TestRenderAPIPortFromConfig: the Xray gRPC API port is a parameter,
// not a literal: render with 10086 and the api inbound moves with it.
func TestRenderAPIPortFromConfig(t *testing.T) {
	data, _, _, err := renderXrayConfig(testRealityDoc(), 10086)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	p := parseXrayJSON(t, data)
	if got := p.inboundByTag(t, "api")["port"]; got != float64(10086) {
		t.Fatalf("api port = %v, want 10086", got)
	}
}

// TestLoadConfigOverrides: explicit config values win over defaults;
// a config without the slice-2 fields gets the defaults (0.1.0
// configs keep working after upgrade).
func TestLoadConfigOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgJSON := `{"panel_url":"https://example.com:11111","node_id":1,` +
		`"cert_file":"/etc/node-backend/certs/node.crt","key_file":"/etc/node-backend/certs/node.key",` +
		`"xray_path":"/opt/xray","xray_config_path":"/opt/xray.json",` +
		`"control_addr":"127.0.0.1:19090","api_port":10086}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfgJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := loadConfig(dir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.XrayPath != "/opt/xray" || cfg.XrayConfigPath != "/opt/xray.json" ||
		cfg.ControlAddr != "127.0.0.1:19090" || cfg.APIPort != 10086 {
		t.Fatalf("explicit config values lost: %+v", cfg)
	}

	dir2 := t.TempDir()
	oldJSON := `{"panel_url":"https://example.com:11111","node_id":1,` +
		`"cert_file":"/etc/node-backend/certs/node.crt","key_file":"/etc/node-backend/certs/node.key"}`
	if err := os.WriteFile(filepath.Join(dir2, "config.json"), []byte(oldJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	old, err := loadConfig(dir2)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if old.XrayPath != defaultXrayPath || old.ControlAddr != defaultControlAddr || old.APIPort != defaultAPIPort {
		t.Fatalf("defaults not applied: %+v", old)
	}
	if old.XrayConfigPath != filepath.Join(dir2, "xray.json") {
		t.Fatalf("xray config path = %q, want <config-dir>/xray.json", old.XrayConfigPath)
	}
}

// TestApplyConfigRealXray: apply() with the real Xray binary must
// write xray.json, pass `xray run -test`, and start the child. A
// second apply of the same doc must not restart Xray. (Regression:
// the temp file used for validation must keep a .json suffix — Xray
// picks the config format from the extension and rejects a bare .tmp.)
func TestApplyConfigRealXray(t *testing.T) {
	xrayBin := os.Getenv("XRAY_BIN")
	if xrayBin == "" {
		xrayBin = filepath.Join(os.Getenv("HOME"), "workspace", "toolchains", "xray", "xray")
	}
	if _, err := os.Stat(xrayBin); err != nil {
		t.Skipf("no xray binary at %s", xrayBin)
	}
	dir := t.TempDir()
	cfg := &Config{
		XrayPath: xrayBin, XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10085, ControlAddr: "127.0.0.1:0",
	}
	sup := newSupervisor(xrayBin, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup)
	defer sup.Stop()

	doc := testRealityDoc()
	doc.Inbounds[0].Port = 24443
	doc.Inbounds[0].Listen = "127.0.0.1"
	doc.Inbounds[1].Port = 28443
	doc.Inbounds[1].Listen = "127.0.0.1"
	if err := ap.apply(doc); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := os.Stat(cfg.XrayConfigPath); err != nil {
		t.Fatalf("xray.json not written: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	pid1 := sup.Status().PID
	if ap.appliedVersion() != doc.ConfigVersion {
		t.Fatalf("applied version = %d, want %d", ap.appliedVersion(), doc.ConfigVersion)
	}
	if err := ap.apply(doc); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if pid := sup.Status().PID; pid != pid1 {
		t.Fatalf("unchanged config restarted xray: %d -> %d", pid1, pid)
	}
}

// TestRenderDeterministic: same doc renders byte-identical output
// (restart decisions rely on the SHA).
func TestRenderDeterministic(t *testing.T) {
	a, shaA, _, err := renderXrayConfig(testRealityDoc(), 10085)
	if err != nil {
		t.Fatalf("render #1: %v", err)
	}
	b, shaB, _, err := renderXrayConfig(testRealityDoc(), 10085)
	if err != nil {
		t.Fatalf("render #2: %v", err)
	}
	if shaA != shaB || string(a) != string(b) {
		t.Fatalf("render is not deterministic: %s vs %s", shaA, shaB)
	}
}
