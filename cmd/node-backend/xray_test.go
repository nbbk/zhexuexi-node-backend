package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
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
	data, sha, skipped, _, err := renderXrayConfig(testRealityDoc(), 10085, "")
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
// rendered; other protocols are skipped, not errors. (Trojan is an
// Xray inbound since slice 7, so vmess stands in for "other".)
func TestRenderSkipsDisabledAndNonVLESS(t *testing.T) {
	doc := testRealityDoc()
	doc.Inbounds[0].Enabled = false
	doc.Inbounds = append(doc.Inbounds, configInbound{
		InboundID: 4, InboundTag: "vmess-443", Protocol: "vmess",
		Transport: "tcp", Security: "tls", Port: 444, Enabled: true,
	})
	data, _, skipped, _, err := renderXrayConfig(doc, 10085, "")
	if err != nil {
		t.Fatalf("renderXrayConfig: %v", err)
	}
	p := parseXrayJSON(t, data)
	for _, in := range p.inbounds(t) {
		if in["tag"] == "reality-443" || in["tag"] == "vmess-443" {
			t.Fatalf("inbound %v should not be rendered", in["tag"])
		}
	}
	want := map[string]bool{"hy2-443": true, "vmess-443": true}
	for _, s := range skipped {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Fatalf("skipped = %v, missing %v", skipped, want)
	}
}

// TestRenderErrors: port conflicts and missing REALITY keys are hard
// errors (nothing is applied). A TLS inbound without its certificate
// is not an error: it is skipped (needsCert) so one inbound without
// its certificate never blocks the rest of the config (slice 7).
func TestRenderErrors(t *testing.T) {
	// Two enabled Xray inbounds on the same TCP port.
	doc := testRealityDoc()
	doc.Inbounds = append(doc.Inbounds, configInbound{
		InboundID: 9, InboundTag: "reality-dup", Protocol: "vless",
		Transport: "reality", Security: "reality", Port: 443,
		SNI: "www.example.com", RealityPrivateKey: "KMI9fIon8C4SCjMV5lydfxlLmiV9aKEvhRi73M2uf38",
		RealityShortID: "ffffffff", Enabled: true,
	})
	if _, _, _, _, err := renderXrayConfig(doc, 10085, ""); err == nil || !strings.Contains(err.Error(), "443") {
		t.Fatalf("port conflict should error with the port, got %v", err)
	}

	// REALITY inbound without a private key.
	doc = testRealityDoc()
	doc.Inbounds[0].RealityPrivateKey = ""
	if _, _, _, _, err := renderXrayConfig(doc, 10085, ""); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("missing private key should error, got %v", err)
	}

	// TLS inbound without certs (slice 7 ships them): skipped, not
	// an error, and the rest of the config still renders.
	doc = testRealityDoc()
	doc.Inbounds = append(doc.Inbounds, configInbound{
		InboundID: 10, InboundTag: "tls-443", Protocol: "vless",
		Transport: "tcp", Security: "tls", Port: 8443,
		SNI: "node1.example.com", Flow: "xtls-rprx-vision", Enabled: true,
	})
	data, _, _, needsCert, err := renderXrayConfig(doc, 10085, "")
	if err != nil {
		t.Fatalf("TLS without certs must skip, not error, got %v", err)
	}
	if len(needsCert) != 1 || needsCert[0] != "tls-443" {
		t.Fatalf("needsCert = %v, want [tls-443]", needsCert)
	}
	p := parseXrayJSON(t, data)
	for _, in := range p.inbounds(t) {
		if in["tag"] == "tls-443" {
			t.Fatalf("tls-443 without a certificate must not be rendered")
		}
	}

	// Bad API port.
	if _, _, _, _, err := renderXrayConfig(testRealityDoc(), 0, ""); err == nil {
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
	data, _, _, _, err := renderXrayConfig(testRealityDoc(), 10085, "")
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
	data, _, _, _, err := renderXrayConfig(doc, 10085, "")
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
	if _, _, _, _, err := renderXrayConfig(doc, 10085, ""); err == nil {
		t.Fatalf("invalid listen address should fail the render")
	}
}

// TestRenderAPIPortFromConfig: the Xray gRPC API port is a parameter,
// not a literal: render with 10086 and the api inbound moves with it.
func TestRenderAPIPortFromConfig(t *testing.T) {
	data, _, _, _, err := renderXrayConfig(testRealityDoc(), 10086, "")
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
	ap := newConfigApplier(cfg, sup, nil)
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
	a, shaA, _, _, err := renderXrayConfig(testRealityDoc(), 10085, "")
	if err != nil {
		t.Fatalf("render #1: %v", err)
	}
	b, shaB, _, _, err := renderXrayConfig(testRealityDoc(), 10085, "")
	if err != nil {
		t.Fatalf("render #2: %v", err)
	}
	if shaA != shaB || string(a) != string(b) {
		t.Fatalf("render is not deterministic: %s vs %s", shaA, shaB)
	}
}

// testBackupDoc builds a panel config doc with the three slice 6
// backup inbounds enabled (SS, SS2022, SOCKS5) plus one disabled SS
// that must not render, on top of the default trio.
func testBackupDoc() *nodeConfig {
	doc := testRealityDoc()
	doc.Inbounds = append(doc.Inbounds,
		configInbound{
			InboundID: 11, InboundTag: "ss-8388", Protocol: "shadowsocks",
			Transport: "tcp", Security: "none", Port: 8388,
			SSMethod: "aes-128-gcm", SSPassword: "test-ss-password", Enabled: true,
		},
		configInbound{
			InboundID: 12, InboundTag: "ss2022-8389", Protocol: "shadowsocks",
			Transport: "tcp", Security: "none", Port: 8389,
			// SS2022 passwords are base64-encoded keys of the exact
			// key length (16 bytes for 2022-blake3-aes-128-gcm):
			// Xray rejects the config otherwise ("bad key"). The
			// panel must generate SS2022 passwords in this form;
			// the agent renders what the panel sends.
			SSMethod: "2022-blake3-aes-128-gcm", SSPassword: "AAECAwQFBgcICQoLDA0ODw==", Enabled: true,
		},
		configInbound{
			InboundID: 13, InboundTag: "socks-1080", Protocol: "socks",
			Transport: "tcp", Security: "none", Port: 1080,
			SocksUsername: "s5user", SocksPassword: "test-s5-password", Enabled: true,
		},
		configInbound{
			InboundID: 14, InboundTag: "ss-off", Protocol: "shadowsocks",
			Transport: "tcp", Security: "none", Port: 8390,
			SSMethod: "aes-256-gcm", SSPassword: "unused", Enabled: false,
		},
	)
	return doc
}

// TestRenderShadowsocksInbound: SS and SS2022 render as Xray
// "shadowsocks" inbounds with method + the inbound-shared password;
// the only difference between them is the method string. A disabled
// SS inbound renders nothing and listens on nothing.
func TestRenderShadowsocksInbound(t *testing.T) {
	data, _, skipped, _, err := renderXrayConfig(testBackupDoc(), 10085, "")
	if err != nil {
		t.Fatalf("renderXrayConfig: %v", err)
	}
	if len(skipped) != 1 || skipped[0] != "hy2-443" {
		t.Fatalf("skipped = %v, want [hy2-443]", skipped)
	}
	p := parseXrayJSON(t, data)
	ins := p.inbounds(t)
	if len(ins) != 6 {
		t.Fatalf("rendered %d inbounds, want 6 (api + reality + xhttp + ss + ss2022 + socks)", len(ins))
	}
	for _, in := range ins {
		if in["tag"] == "ss-off" {
			t.Fatalf("disabled inbound ss-off must not be rendered")
		}
	}

	ss := p.inboundByTag(t, "ss-8388")
	if ss["protocol"] != "shadowsocks" || ss["port"] != float64(8388) {
		t.Fatalf("ss inbound wrong: %v", ss)
	}
	ssSettings := strMap(t, ss["settings"])
	if ssSettings["method"] != "aes-128-gcm" || ssSettings["password"] != "test-ss-password" {
		t.Fatalf("ss settings wrong: %v", ssSettings)
	}
	if _, hasStream := ss["streamSettings"]; hasStream {
		t.Fatalf("ss inbound must not carry streamSettings (UDP is Xray's default): %v", ss)
	}

	ss2022 := p.inboundByTag(t, "ss2022-8389")
	if ss2022["protocol"] != "shadowsocks" || ss2022["port"] != float64(8389) {
		t.Fatalf("ss2022 inbound wrong: %v", ss2022)
	}
	s2022Settings := strMap(t, ss2022["settings"])
	if s2022Settings["method"] != "2022-blake3-aes-128-gcm" || s2022Settings["password"] != "AAECAwQFBgcICQoLDA0ODw==" {
		t.Fatalf("ss2022 settings wrong: %v", s2022Settings)
	}
}

// TestRenderSocksInbound: SOCKS5 renders as Xray "socks" with
// password auth and exactly one account (user/pass from the panel).
func TestRenderSocksInbound(t *testing.T) {
	data, _, _, _, err := renderXrayConfig(testBackupDoc(), 10085, "")
	if err != nil {
		t.Fatalf("renderXrayConfig: %v", err)
	}
	p := parseXrayJSON(t, data)
	s5 := p.inboundByTag(t, "socks-1080")
	if s5["protocol"] != "socks" || s5["port"] != float64(1080) {
		t.Fatalf("socks inbound wrong: %v", s5)
	}
	settings := strMap(t, s5["settings"])
	if settings["auth"] != "password" {
		t.Fatalf("socks auth = %v, want password", settings["auth"])
	}
	accounts, _ := settings["accounts"].([]any)
	if len(accounts) != 1 {
		t.Fatalf("socks accounts = %d, want 1", len(accounts))
	}
	acc := strMap(t, accounts[0])
	if acc["user"] != "s5user" || acc["pass"] != "test-s5-password" {
		t.Fatalf("socks account wrong: %v", acc)
	}
	if _, hasStream := s5["streamSettings"]; hasStream {
		t.Fatalf("socks inbound must not carry streamSettings: %v", s5)
	}
}

// TestRenderBackupProtocolErrors: an enabled backup inbound with
// missing credentials (or a bad port) is a hard error, not a silent
// skip — the user explicitly asked for it.
func TestRenderBackupProtocolErrors(t *testing.T) {
	base := func() *nodeConfig {
		return &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 1, Inbounds: []configInbound{
			{InboundID: 1, InboundTag: "ss-8388", Protocol: "shadowsocks",
				Transport: "tcp", Security: "none", Port: 8388,
				SSMethod: "aes-128-gcm", SSPassword: "pw", Enabled: true},
		}}
	}
	doc := base()
	doc.Inbounds[0].SSMethod = ""
	if _, _, _, _, err := renderXrayConfig(doc, 10085, ""); err == nil || !strings.Contains(err.Error(), "method") {
		t.Fatalf("SS without method should error, got %v", err)
	}
	doc = base()
	doc.Inbounds[0].SSPassword = ""
	if _, _, _, _, err := renderXrayConfig(doc, 10085, ""); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("SS without password should error, got %v", err)
	}
	doc = base()
	doc.Inbounds[0].Port = 0
	if _, _, _, _, err := renderXrayConfig(doc, 10085, ""); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("SS with port 0 should error, got %v", err)
	}
	socksDoc := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 1, Inbounds: []configInbound{
		{InboundID: 2, InboundTag: "socks-1080", Protocol: "socks",
			Transport: "tcp", Security: "none", Port: 1080,
			SocksUsername: "u", SocksPassword: "p", Enabled: true},
	}}
	socksDoc.Inbounds[0].SocksUsername = ""
	if _, _, _, _, err := renderXrayConfig(socksDoc, 10085, ""); err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("SOCKS without username should error, got %v", err)
	}
	socksDoc.Inbounds[0].SocksUsername = "u"
	socksDoc.Inbounds[0].SocksPassword = ""
	if _, _, _, _, err := renderXrayConfig(socksDoc, 10085, ""); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("SOCKS without password should error, got %v", err)
	}
}

// TestRenderPortConflictWithBackupProtocols: the TCP port conflict
// check covers the slice 6 inbounds too — SS/SOCKS5 listen on TCP,
// so a clash with a VLESS inbound (or with each other) is an error.
func TestRenderPortConflictWithBackupProtocols(t *testing.T) {
	// SS on 443, already taken by reality-443.
	doc := testBackupDoc()
	doc.Inbounds[3].Port = 443
	if _, _, _, _, err := renderXrayConfig(doc, 10085, ""); err == nil || !strings.Contains(err.Error(), "443") {
		t.Fatalf("SS on 443 should conflict with reality-443, got %v", err)
	}
	// SOCKS5 on 8443, already taken by xhttp-443.
	doc = testBackupDoc()
	doc.Inbounds[5].Port = 8443
	if _, _, _, _, err := renderXrayConfig(doc, 10085, ""); err == nil || !strings.Contains(err.Error(), "8443") {
		t.Fatalf("SOCKS on 8443 should conflict with xhttp-443, got %v", err)
	}
	// SS2022 and SOCKS5 on the same port.
	doc = testBackupDoc()
	doc.Inbounds[5].Port = 8389
	if _, _, _, _, err := renderXrayConfig(doc, 10085, ""); err == nil || !strings.Contains(err.Error(), "8389") {
		t.Fatalf("SS2022 and SOCKS on the same port should conflict, got %v", err)
	}
}

// TestRenderSkippedUnchanged: slice 6 does not change the skip
// rule — HY2/TUIC/AnyTLS/VMess are still skipped (sing-box core),
// never rendered by the Xray side. Trojan moved to the Xray side in
// slice 7: without its certificate file it lands in needsCert, not
// in skipped.
func TestRenderSkippedUnchanged(t *testing.T) {
	doc := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 1, Inbounds: []configInbound{
		{InboundID: 1, InboundTag: "hy2-443", Protocol: "hysteria2", Transport: "quic", Security: "tls", Port: 443, Enabled: true},
		{InboundID: 2, InboundTag: "tuic-443", Protocol: "tuic", Transport: "quic", Security: "tls", Port: 444, Enabled: true},
		{InboundID: 3, InboundTag: "anytls-443", Protocol: "anytls", Transport: "tcp", Security: "tls", Port: 445, Enabled: true},
		{InboundID: 4, InboundTag: "trojan-443", Protocol: "trojan", Transport: "tcp", Security: "tls", Port: 446, Enabled: true},
		{InboundID: 5, InboundTag: "vmess-443", Protocol: "vmess", Transport: "tcp", Security: "none", Port: 447, Enabled: true},
	}}
	data, _, skipped, needsCert, err := renderXrayConfig(doc, 10085, "")
	if err != nil {
		t.Fatalf("renderXrayConfig: %v", err)
	}
	want := []string{"anytls-443", "hy2-443", "tuic-443", "vmess-443"}
	if len(skipped) != len(want) {
		t.Fatalf("skipped = %v, want %v", skipped, want)
	}
	for i, w := range want {
		if skipped[i] != w {
			t.Fatalf("skipped = %v, want %v", skipped, want)
		}
	}
	if len(needsCert) != 1 || needsCert[0] != "trojan-443" {
		t.Fatalf("needsCert = %v, want [trojan-443]", needsCert)
	}
	p := parseXrayJSON(t, data)
	if len(p.inbounds(t)) != 1 {
		t.Fatalf("rendered %d inbounds, want 1 (api only)", len(p.inbounds(t)))
	}
}

// TestValidateXrayConfigWithBackupProtocols: the real Xray binary
// (pinned 26.11.9) must accept a rendered config containing the
// slice 6 inbounds.
func TestValidateXrayConfigWithBackupProtocols(t *testing.T) {
	xrayBin := os.Getenv("XRAY_BIN")
	if xrayBin == "" {
		xrayBin = filepath.Join(os.Getenv("HOME"), "workspace", "toolchains", "xray", "xray")
	}
	if _, err := os.Stat(xrayBin); err != nil {
		t.Skipf("no xray binary at %s", xrayBin)
	}
	data, _, _, _, err := renderXrayConfig(testBackupDoc(), 10085, "")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := validateXrayConfig(xrayBin, cfgPath); err != nil {
		t.Fatalf("real xray rejected the config with SS/SOCKS5 inbounds: %v", err)
	}
}

// --- Slice 6 e2e helpers: a minimal Shadowsocks AEAD (aes-128-gcm)
// TCP client and a SOCKS5 client, speaking to the real Xray binary.
// Only the TCP path is exercised: the sandbox forbids UDP sockets,
// so SS/SOCKS5 UDP (and HY2/TUIC) stay for pilot-machine acceptance.

// ssEvpKey derives the shadowsocks master key with EVP_BytesToKey
// (MD5, count 1), the same derivation Xray uses.
func ssEvpKey(password string, keyLen int) []byte {
	var key []byte
	var prev []byte
	for len(key) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	return key[:keyLen]
}

// ssSubkey derives the per-session AEAD subkey with HKDF-SHA1
// (salt = the session salt, info "ss-subkey").
func ssSubkey(masterKey, salt []byte) []byte {
	mac := hmac.New(sha1.New, salt)
	mac.Write(masterKey)
	prk := mac.Sum(nil)
	mac = hmac.New(sha1.New, prk)
	mac.Write([]byte("ss-subkey"))
	mac.Write([]byte{0x01})
	return mac.Sum(nil)[:len(masterKey)]
}

func ssAEAD(subkey []byte) cipher.AEAD {
	block, err := aes.NewCipher(subkey)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// ssNonce returns the 12-byte AEAD nonce for chunk counter n.
// Shadowsocks increments the nonce little-endian (libsodium's
// sodium_increment convention): counter 1 is 01 00 ... 00, not
// 00 ... 01. Counter 0 is all zeros either way.
func ssNonce(n uint64) []byte {
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[:8], n)
	return nonce
}

// ssWriteChunk writes one AEAD chunk: sealed length (nonce n) then
// sealed payload (nonce n+1).
func ssWriteChunk(w io.Writer, aead cipher.AEAD, nonceCounter uint64, payload []byte) error {
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(payload)))
	sealedLen := aead.Seal(nil, ssNonce(nonceCounter), lenBuf, nil)
	if _, err := w.Write(sealedLen); err != nil {
		return err
	}
	sealed := aead.Seal(nil, ssNonce(nonceCounter+1), payload, nil)
	_, err := w.Write(sealed)
	return err
}

// ssReadChunk reads one AEAD chunk (sealed length, then sealed payload).
func ssReadChunk(r io.Reader, aead cipher.AEAD, nonceCounter uint64) ([]byte, error) {
	sealedLen := make([]byte, 2+aead.Overhead())
	if _, err := io.ReadFull(r, sealedLen); err != nil {
		return nil, err
	}
	lenBuf, err := aead.Open(nil, ssNonce(nonceCounter), sealedLen, nil)
	if err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf))
	sealed := make([]byte, n+aead.Overhead())
	if _, err := io.ReadFull(r, sealed); err != nil {
		return nil, err
	}
	return aead.Open(nil, ssNonce(nonceCounter+1), sealed, nil)
}

// ssRequest sends one AEAD chunk (address header + payload) through
// a shadowsocks (aes-128-gcm) inbound at ssAddr with password, and
// returns the first response chunk.
func ssRequest(t *testing.T, ssAddr, password string, header, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", ssAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SS inbound: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	masterKey := ssEvpKey(password, 16)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand salt: %v", err)
	}
	if _, err := conn.Write(salt); err != nil {
		t.Fatalf("write salt: %v", err)
	}
	aead := ssAEAD(ssSubkey(masterKey, salt))
	if err := ssWriteChunk(conn, aead, 0, append(header, payload...)); err != nil {
		t.Fatalf("write SS chunk: %v", err)
	}
	respSalt := make([]byte, 16)
	if _, err := io.ReadFull(conn, respSalt); err != nil {
		t.Fatalf("read response salt: %v", err)
	}
	respAEAD := ssAEAD(ssSubkey(masterKey, respSalt))
	resp, err := ssReadChunk(conn, respAEAD, 0)
	if err != nil {
		t.Fatalf("read SS response chunk: %v", err)
	}
	return resp
}

// socks5DialThrough connects to targetAddr through a SOCKS5 inbound
// at s5Addr with username/password auth, sends payload, and returns
// what the target echoed back.
func socks5DialThrough(t *testing.T, s5Addr, user, pass string, targetAddr *net.TCPAddr, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", s5Addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 inbound: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// Greeting: version 5, 1 method, username/password (0x02).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if method[0] != 0x05 || method[1] != 0x02 {
		t.Fatalf("method selection = %v, want [5 2] (username/password)", method)
	}
	// Username/password auth (RFC 1929).
	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, []byte(user)...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, []byte(pass)...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if authResp[0] != 0x01 || authResp[1] != 0x00 {
		t.Fatalf("auth response = %v, want [1 0] (success)", authResp)
	}
	// CONNECT to the echo server.
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, targetAddr.IP.To4()...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetAddr.Port))
	req = append(req, portBuf...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("CONNECT reply = %v, want success", rep)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	return buf
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// TestBackupProtocolsRealXray starts the real Xray binary with only
// the slice 6 inbounds (SS + SOCKS5, loopback only) and proves the
// TCP path end to end. The two legs use different targets on purpose:
//   - SOCKS5 goes to a local echo server (bytes come back unchanged).
//     SOCKS has no private-target block, so loopback works.
//   - SS goes to a public HTTP target (1.1.1.1:80, literal IP so no
//     DNS is involved). Xray's freedom outbound blocks
//     shadowsocks-originated traffic to private IPs by default
//     (defaultBlockPrivateRule: SS must not be usable to reach the
//     node's own loopback/LAN services), so a loopback echo target
//     is blackholed by design and cannot prove the SS path — and in
//     this sandbox every domain resolves to 198.18.0.0/15, which
//     Xray's private-IP matcher also covers, so a domain target
//     does not help either. If the sandbox cannot reach 1.1.1.1:80
//     directly the SS leg is skipped; the SOCKS leg still runs.
//
// Wrong SOCKS5 password must be refused. UDP is not exercised here
// (the sandbox forbids UDP sockets); SS and SOCKS5 UDP stay for
// pilot-machine acceptance.
func TestBackupProtocolsRealXray(t *testing.T) {
	xrayBin := os.Getenv("XRAY_BIN")
	if xrayBin == "" {
		xrayBin = filepath.Join(os.Getenv("HOME"), "workspace", "toolchains", "xray", "xray")
	}
	if _, err := os.Stat(xrayBin); err != nil {
		t.Skipf("no xray binary at %s", xrayBin)
	}
	// Local echo server: whatever arrives comes back unchanged.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	echoAddr := echoLn.Addr().(*net.TCPAddr)

	ssPort := freeLoopbackPort(t)
	s5Port := freeLoopbackPort(t)
	doc := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 9, Inbounds: []configInbound{
		{InboundID: 11, InboundTag: "ss-8388", Protocol: "shadowsocks",
			Transport: "tcp", Security: "none", Port: ssPort, Listen: "127.0.0.1",
			SSMethod: "aes-128-gcm", SSPassword: "test-ss-password", Enabled: true},
		{InboundID: 13, InboundTag: "socks-1080", Protocol: "socks",
			Transport: "tcp", Security: "none", Port: s5Port, Listen: "127.0.0.1",
			SocksUsername: "s5user", SocksPassword: "test-s5-password", Enabled: true},
	}}
	dir := t.TempDir()
	cfg := &Config{
		XrayPath: xrayBin, XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10087, ControlAddr: "127.0.0.1:0",
	}
	sup := newSupervisor(xrayBin, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	defer sup.Stop()
	if err := ap.apply(doc); err != nil {
		t.Fatalf("apply: %v", err)
	}
	waitFor(t, 10*time.Second, "xray to start", sup.IsRunning)

	ssAddr := net.JoinHostPort("127.0.0.1", itoa(ssPort))
	s5Addr := net.JoinHostPort("127.0.0.1", itoa(s5Port))
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", ssAddr, time.Second)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SS inbound never listened on %s: %v", ssAddr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// SS leg: public HTTP target. Skip just this leg (not the whole
	// test) when the sandbox cannot reach 1.1.1.1:80 directly.
	if c, err := net.DialTimeout("tcp", "1.1.1.1:80", 5*time.Second); err != nil {
		t.Logf("cannot reach 1.1.1.1:80 directly (%v); skipping the SS leg, SOCKS leg still runs", err)
	} else {
		c.Close()
		// ATYP 0x01 (IPv4) + 1.1.1.1 + port 80.
		ipHeader := []byte{0x01, 1, 1, 1, 1, 0x00, 0x50}
		got := ssRequest(t, ssAddr, "test-ss-password", ipHeader,
			[]byte("GET / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n"))
		if !strings.HasPrefix(string(got), "HTTP/") {
			t.Fatalf("SS response = %q, want an HTTP response head", got)
		}
	}

	// SOCKS5 leg: local echo server (loopback is fine for SOCKS).
	got := socks5DialThrough(t, s5Addr, "s5user", "test-s5-password", echoAddr, []byte("hello-s5"))
	if string(got) != "hello-s5" {
		t.Fatalf("SOCKS5 echo = %q, want %q", got, "hello-s5")
	}

	// Wrong SOCKS5 password must fail auth (connection closed, no CONNECT).
	conn, err := net.DialTimeout("tcp", s5Addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 for bad-password check: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte{0x05, 0x01, 0x02})
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	_, _ = conn.Write([]byte{0x01, 0x06, 's', '5', 'u', 's', 'e', 'r', 0x05, 'w', 'r', 'o', 'n', 'g'})
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if authResp[1] == 0x00 {
		t.Fatalf("SOCKS5 accepted a wrong password")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
