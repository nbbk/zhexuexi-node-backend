package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nbbk/zhexuexi-node-backend/cmd/node-backend/v2rayapi"
)

// realSingboxBin mirrors realXrayBin: the sing-box binary under test,
// from SINGBOX_BIN or the pinned custom build. The custom build is
// required (it is the only one with the V2Ray API stats service,
// build plan §9.4); the official binary FATALs on the rendered
// config. Tests using it skip when the binary is absent.
func realSingboxBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		bin = filepath.Join(os.Getenv("HOME"), "workspace", "toolchains", "sing-box-custom", "sing-box-1.14.4-with-v2ray-api")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("no sing-box binary at %s", bin)
	}
	return bin
}

// writeTestCert generates a self-signed certificate for domain and
// writes it as <ref>.crt / <ref>.key into certsDir (the slice 5
// interim contract: <config-dir>/certs/<certRef>.crt/.key).
func writeTestCert(t *testing.T, certsDir string, ref int64, domain string) {
	t.Helper()
	if err := os.MkdirAll(certsDir, 0o700); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(certsDir, fmt.Sprintf("%d.crt", ref)), certPEM, 0o600); err != nil {
		t.Fatalf("write crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certsDir, fmt.Sprintf("%d.key", ref)), keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// testSingboxDoc is a panel config with one inbound per sing-box
// protocol plus one VLESS inbound (Xray's, skipped here). Ports are
// high loopback ports so the real binary can bind them in tests.
func testSingboxDoc() *nodeConfig {
	return &nodeConfig{
		OK: true, NodeID: 1, ConfigVersion: 5,
		Inbounds: []configInbound{
			{InboundTag: "hy2-443", Protocol: "hysteria2", Transport: "quic", Security: "tls", Port: 34443, Listen: "127.0.0.1", SNI: "node.example.com", CertRef: 1, Enabled: true},
			{InboundTag: "tuic-443", Protocol: "tuic", Transport: "quic", Security: "tls", Port: 34444, Listen: "127.0.0.1", SNI: "node.example.com", CertRef: 1, Enabled: true},
			{InboundTag: "anytls-443", Protocol: "anytls", Transport: "tcp", Security: "tls", Port: 34445, Listen: "127.0.0.1", SNI: "node.example.com", CertRef: 1, Enabled: true},
			{InboundTag: "reality-443", Protocol: "vless", Transport: "reality", Security: "reality", Port: 443, Listen: "0.0.0.0", SNI: "www.microsoft.com", RealityPrivateKey: "k", RealityShortID: "s", Enabled: true},
		},
		Users: []configUser{
			{UserID: "subuser:su-1", Kind: "subuser", ID: "su-1", Name: "u1", Email: "u-sub-su-1@node", VLESSUUID: "11111111-2222-3333-4444-555555555555"},
			{UserID: "subuser:su-2", Kind: "subuser", ID: "su-2", Name: "u2", Email: "u-sub-su-2@node", VLESSUUID: "22222222-3333-4444-5555-666666666666"},
			{UserID: "subuser:su-3", Kind: "subuser", ID: "su-3", Name: "u3", Email: "u-sub-su-3@node", VLESSUUID: "33333333-4444-5555-6666-777777777777", Disabled: true},
			{UserID: "subuser:su-4", Kind: "subuser", ID: "su-4", Name: "u4", Email: "u-sub-su-4@node"},
		},
	}
}

func decodeSingbox(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode sing-box config: %v", err)
	}
	return doc
}

func singboxInbounds(t *testing.T, doc map[string]any) []map[string]any {
	t.Helper()
	raw, ok := doc["inbounds"].([]any)
	if !ok {
		t.Fatalf("inbounds missing: %v", doc)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("inbound not an object: %v", r)
		}
		out = append(out, m)
	}
	return out
}

func findInbound(t *testing.T, inbounds []map[string]any, tag string) map[string]any {
	t.Helper()
	for _, in := range inbounds {
		if in["tag"] == tag {
			return in
		}
	}
	t.Fatalf("inbound %s not found in %v", tag, inbounds)
	return nil
}

// TestRenderSingboxConfig: HY2/TUIC/AnyTLS render with the UUID
// credential mapping; the VLESS inbound is skipped.
func TestRenderSingboxConfig(t *testing.T) {
	certsDir := filepath.Join(t.TempDir(), "certs")
	writeTestCert(t, certsDir, 1, "node.example.com")
	data, _, skipped, needsCert, err := renderSingboxConfig(testSingboxDoc(), certsDir)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(needsCert) != 0 {
		t.Fatalf("needsCert = %v, want none", needsCert)
	}
	if len(skipped) != 1 || skipped[0] != "reality-443" {
		t.Fatalf("skipped = %v, want [reality-443]", skipped)
	}
	doc := decodeSingbox(t, data)
	inbounds := singboxInbounds(t, doc)
	if len(inbounds) != 3 {
		t.Fatalf("inbounds = %d, want 3", len(inbounds))
	}

	hy2 := findInbound(t, inbounds, "hy2-443")
	if hy2["type"] != "hysteria2" || hy2["listen_port"] != float64(34443) || hy2["listen"] != "127.0.0.1" {
		t.Fatalf("hy2 inbound wrong: %v", hy2)
	}
	users, _ := hy2["users"].([]any)
	if len(users) != 2 {
		t.Fatalf("hy2 users = %d, want 2 (disabled + no-UUID skipped)", len(users))
	}
	if users[0].(map[string]any)["password"] != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("hy2 password is not the user UUID: %v", users[0])
	}
	if users[0].(map[string]any)["name"] != "u-sub-su-1@node" {
		t.Fatalf("hy2 name is not the user email: %v", users[0])
	}
	tls, _ := hy2["tls"].(map[string]any)
	if tls["enabled"] != true || tls["server_name"] != "node.example.com" || tls["certificate_path"] != filepath.Join(certsDir, "1.crt") || tls["key_path"] != filepath.Join(certsDir, "1.key") {
		t.Fatalf("hy2 tls wrong: %v", tls)
	}
	if alpn, _ := tls["alpn"].([]any); len(alpn) != 1 || alpn[0] != "h3" {
		t.Fatalf("hy2 alpn wrong: %v", tls["alpn"])
	}

	tuic := findInbound(t, inbounds, "tuic-443")
	if tuic["type"] != "tuic" || tuic["congestion_control"] != "bbr" {
		t.Fatalf("tuic inbound wrong: %v", tuic)
	}
	tusers, _ := tuic["users"].([]any)
	if tusers[0].(map[string]any)["uuid"] != "11111111-2222-3333-4444-555555555555" || tusers[0].(map[string]any)["password"] != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("tuic user is not uuid+password=UUID: %v", tusers[0])
	}
	if tusers[0].(map[string]any)["name"] != "u-sub-su-1@node" {
		t.Fatalf("tuic name is not the user email: %v", tusers[0])
	}

	anytls := findInbound(t, inbounds, "anytls-443")
	if anytls["type"] != "anytls" || anytls["listen_port"] != float64(34445) {
		t.Fatalf("anytls inbound wrong: %v", anytls)
	}
	ausers, _ := anytls["users"].([]any)
	if ausers[0].(map[string]any)["name"] != "u-sub-su-1@node" || ausers[0].(map[string]any)["password"] != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("anytls user wrong: %v", ausers[0])
	}
	if atls, _ := anytls["tls"].(map[string]any); atls["alpn"] != nil {
		t.Fatalf("anytls must not set alpn: %v", atls)
	}

	// V2Ray API stats + routing scaffolding.
	exp, _ := doc["experimental"].(map[string]any)
	v2ray, _ := exp["v2ray_api"].(map[string]any)
	if v2ray["listen"] != defaultSingboxV2RayAddr {
		t.Fatalf("v2ray_api listen wrong: %v", v2ray)
	}
	stats, _ := v2ray["stats"].(map[string]any)
	if stats["enabled"] != true {
		t.Fatalf("v2ray_api stats not enabled: %v", stats)
	}
	if tags, _ := stats["inbounds"].([]any); len(tags) != 3 || tags[0] != "anytls-443" || tags[1] != "hy2-443" || tags[2] != "tuic-443" {
		t.Fatalf("v2ray_api stats inbounds = %v, want sorted [anytls-443 hy2-443 tuic-443]", tags)
	}
	if names, _ := stats["users"].([]any); len(names) != 2 || names[0] != "u-sub-su-1@node" || names[1] != "u-sub-su-2@node" {
		t.Fatalf("v2ray_api stats users = %v, want [u-sub-su-1@node u-sub-su-2@node]", names)
	}
	route, _ := doc["route"].(map[string]any)
	if route["final"] != "direct" {
		t.Fatalf("route final wrong: %v", route)
	}
	obs, _ := doc["outbounds"].([]any)
	if len(obs) != 2 {
		t.Fatalf("outbounds = %d, want 2", len(obs))
	}
}

// TestRenderSingboxConfigNoCert: an inbound whose certificate is not
// on disk yet is skipped (needsCert), not rendered without TLS.
func TestRenderSingboxConfigNoCert(t *testing.T) {
	certsDir := filepath.Join(t.TempDir(), "certs")
	writeTestCert(t, certsDir, 1, "node.example.com")
	doc := testSingboxDoc()
	doc.Inbounds[0].CertRef = 99 // no such cert on disk; the others resolve
	data, _, skipped, needsCert, err := renderSingboxConfig(doc, certsDir)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(needsCert) != 1 || needsCert[0] != "hy2-443" {
		t.Fatalf("needsCert = %v, want [hy2-443]", needsCert)
	}
	inbounds := singboxInbounds(t, decodeSingbox(t, data))
	if len(inbounds) != 2 {
		t.Fatalf("inbounds = %d, want 2 (hy2 skipped)", len(inbounds))
	}
	if len(skipped) != 1 || skipped[0] != "reality-443" {
		t.Fatalf("skipped = %v, want [reality-443]", skipped)
	}
}

// TestRenderSingboxConfigNoDomain: a sing-box inbound with no SNI or
// domain is an error (the panel must never send it).
func TestRenderSingboxConfigNoDomain(t *testing.T) {
	certsDir := filepath.Join(t.TempDir(), "certs")
	writeTestCert(t, certsDir, 1, "node.example.com")
	doc := testSingboxDoc()
	doc.Inbounds[0].SNI = ""
	if _, _, _, _, err := renderSingboxConfig(doc, certsDir); err == nil {
		t.Fatalf("render without domain must fail")
	}
}

// TestRenderSingboxConfigUDPPortConflict: HY2 and TUIC on the same
// UDP port is an error.
func TestRenderSingboxConfigUDPPortConflict(t *testing.T) {
	certsDir := filepath.Join(t.TempDir(), "certs")
	writeTestCert(t, certsDir, 1, "node.example.com")
	doc := testSingboxDoc()
	doc.Inbounds[1].Port = 34443 // tuic onto hy2's port
	if _, _, _, _, err := renderSingboxConfig(doc, certsDir); err == nil {
		t.Fatalf("UDP port conflict must fail")
	} else if !strings.Contains(err.Error(), "UDP port 34443") {
		t.Fatalf("error %v does not name the port", err)
	}
}

// TestCheckCrossCoreTCPPorts: an Xray TCP inbound and an AnyTLS
// inbound on the same port collide; different ports and the loopback
// API door do not.
func TestCheckCrossCoreTCPPorts(t *testing.T) {
	xray := []byte(`{"inbounds":[{"tag":"api","listen":"127.0.0.1","port":10085},{"tag":"reality-443","listen":"0.0.0.0","port":8443}]}`)
	anytls := []byte(`{"inbounds":[{"tag":"anytls-443","listen":"0.0.0.0","listen_port":8443,"type":"anytls"}]}`)
	if err := checkCrossCoreTCPPorts(xray, anytls); err == nil {
		t.Fatalf("same TCP port across cores must fail")
	} else if !strings.Contains(err.Error(), "8443") {
		t.Fatalf("error %v does not name the port", err)
	}
	anytlsOther := []byte(`{"inbounds":[{"tag":"anytls-443","listen":"0.0.0.0","listen_port":9443,"type":"anytls"}]}`)
	if err := checkCrossCoreTCPPorts(xray, anytlsOther); err != nil {
		t.Fatalf("different ports must pass: %v", err)
	}
	anytlsAPIPort := []byte(`{"inbounds":[{"tag":"anytls-443","listen":"0.0.0.0","listen_port":10085,"type":"anytls"}]}`)
	if err := checkCrossCoreTCPPorts(xray, anytlsAPIPort); err != nil {
		t.Fatalf("loopback API door must not collide: %v", err)
	}
	hy2 := []byte(`{"inbounds":[{"tag":"hy2-443","listen":"0.0.0.0","listen_port":443,"type":"hysteria2"}]}`)
	if err := checkCrossCoreTCPPorts(xray, hy2); err != nil {
		t.Fatalf("UDP inbounds must not collide with TCP: %v", err)
	}
}

// fakeStatsServer is a minimal V2Ray API StatsService backed by a
// fixed counter map, for testing querySingboxStats without a real
// sing-box process.
type fakeStatsServer struct {
	v2rayapi.UnimplementedStatsServiceServer
	counters map[string]int64
}

func (s *fakeStatsServer) QueryStats(ctx context.Context, req *v2rayapi.QueryStatsRequest) (*v2rayapi.QueryStatsResponse, error) {
	resp := &v2rayapi.QueryStatsResponse{}
	for name, v := range s.counters {
		resp.Stat = append(resp.Stat, &v2rayapi.Stat{Name: name, Value: v})
	}
	return resp, nil
}

// TestQuerySingboxStats: the gRPC client reads all counters from a
// fake stats service (service name v2ray.core.app.stats.command.
// StatsService, as the patched generated code uses), and a dead
// address is an error.
func TestQuerySingboxStats(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	v2rayapi.RegisterStatsServiceServer(srv, &fakeStatsServer{counters: map[string]int64{
		"inbound>>>anytls-443>>>traffic>>>uplink":     89,
		"inbound>>>anytls-443>>>traffic>>>downlink":   10485966,
		"user>>>u-sub-su-1@node>>>traffic>>>uplink":   89,
		"user>>>u-sub-su-1@node>>>traffic>>>downlink": 10485966,
	}})
	go srv.Serve(lis)
	defer srv.Stop()
	got, err := querySingboxStats(lis.Addr().String())
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got["inbound>>>anytls-443>>>traffic>>>downlink"] != 10485966 || got["user>>>u-sub-su-1@node>>>traffic>>>downlink"] != 10485966 || got["inbound>>>anytls-443>>>traffic>>>uplink"] != 89 {
		t.Fatalf("counters = %v, want the four test counters", got)
	}
	if _, err := querySingboxStats("127.0.0.1:1"); err == nil {
		t.Fatalf("dead address must fail")
	}
}

// TestSingboxCounterAccumulator: first sample seeds, later samples
// delta per counter (inbound and user separately), a decrease
// (restart) counts the whole sample, unknown shapes are ignored.
func TestSingboxCounterAccumulator(t *testing.T) {
	var a singboxCounterAccumulator
	sample1 := map[string]int64{
		"inbound>>>anytls-443>>>traffic>>>uplink":     100,
		"inbound>>>anytls-443>>>traffic>>>downlink":   200,
		"user>>>u-sub-su-1@node>>>traffic>>>downlink": 200,
	}
	if d := a.delta(sample1); len(d.inbounds) != 0 || len(d.users) != 0 {
		t.Fatalf("first sample delta = %+v, want empty (seed)", d)
	}
	sample2 := map[string]int64{
		"inbound>>>anytls-443>>>traffic>>>uplink":     150,
		"inbound>>>anytls-443>>>traffic>>>downlink":   800,
		"user>>>u-sub-su-1@node>>>traffic>>>downlink": 800,
		"user>>>u-sub-su-2@node>>>traffic>>>downlink": 50,
		"garbage": 999,
	}
	d := a.delta(sample2)
	if d.inbounds["anytls-443"] != [2]int64{50, 600} {
		t.Fatalf("inbound delta = %v, want {50 600}", d.inbounds["anytls-443"])
	}
	if d.users["u-sub-su-1@node"] != [2]int64{0, 600} {
		t.Fatalf("user1 delta = %v, want {0 600}", d.users["u-sub-su-1@node"])
	}
	if d.users["u-sub-su-2@node"] != [2]int64{0, 50} {
		t.Fatalf("user2 delta (new counter) = %v, want {0 50}", d.users["u-sub-su-2@node"])
	}
	if len(d.users) != 2 || len(d.inbounds) != 1 {
		t.Fatalf("delta has extra rows: %+v", d)
	}
	// Restart: counters reset to small values, whole sample is delta.
	sample3 := map[string]int64{
		"inbound>>>anytls-443>>>traffic>>>uplink":     10,
		"inbound>>>anytls-443>>>traffic>>>downlink":   20,
		"user>>>u-sub-su-1@node>>>traffic>>>downlink": 20,
	}
	d = a.delta(sample3)
	if d.inbounds["anytls-443"] != [2]int64{10, 20} {
		t.Fatalf("restart inbound delta = %v, want {10 20}", d.inbounds["anytls-443"])
	}
	if d.users["u-sub-su-1@node"] != [2]int64{0, 20} {
		t.Fatalf("restart user delta = %v, want {0 20}", d.users["u-sub-su-1@node"])
	}
}

// TestSingboxSupervisorRestartOnKill: the generalized supervisor
// restarts a killed sing-box child with a new pid within 5 s.
func TestSingboxSupervisorRestartOnKill(t *testing.T) {
	bin := fakeBinary(t, "sleep 300")
	sup := newCoreSupervisor("sing-box", bin, filepath.Join(t.TempDir(), "sing-box.json"), "run", "-c", "sing-box.json")
	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop()
	waitFor(t, 5*time.Second, "sing-box to start", sup.IsRunning)
	pid1 := sup.Status().PID
	if err := syscall.Kill(pid1, syscall.SIGKILL); err != nil {
		t.Fatalf("kill pid %d: %v", pid1, err)
	}
	started := time.Now()
	waitFor(t, 5*time.Second, "sing-box to restart with a new pid", func() bool {
		st := sup.Status()
		return st.Running && st.PID != pid1 && st.PID > 0
	})
	if took := time.Since(started); took > 5*time.Second {
		t.Fatalf("restart took %s, want <= 5s", took)
	}
	if got := sup.Status().Restarts; got < 1 {
		t.Fatalf("restarts = %d, want >= 1", got)
	}
}

// TestApplySingboxRealBinary: with the real sing-box binary, an apply
// starts sing-box, the V2Ray API answers, a kill restarts it within
// 5 s, and removing all sing-box inbounds stops it.
func TestApplySingboxRealBinary(t *testing.T) {
	bin := realSingboxBin(t)
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")
	writeTestCert(t, certsDir, 1, "node.example.com")
	cfg := &Config{
		XrayPath: "sleep", XrayConfigPath: filepath.Join(dir, "xray.json"),
		SingboxPath: bin, SingboxConfigPath: filepath.Join(dir, "sing-box.json"),
		APIPort: 10087, ControlAddr: "127.0.0.1:0",
	}
	xraySup := newSupervisor("sleep", cfg.XrayConfigPath)
	sbSup := newCoreSupervisor("sing-box", bin, cfg.SingboxConfigPath, "run", "-c", cfg.SingboxConfigPath)
	ap := newConfigApplier(cfg, xraySup, sbSup)
	defer sbSup.Stop()

	xrayEmpty := []byte(`{"inbounds":[]}`)
	doc := testSingboxDoc()
	doc.ConfigVersion = 5
	if err := ap.applySingbox(doc, xrayEmpty); err != nil {
		t.Fatalf("applySingbox: %v", err)
	}
	waitFor(t, 5*time.Second, "sing-box to start", sbSup.IsRunning)
	pid1 := sbSup.Status().PID
	if pid1 <= 0 {
		t.Fatalf("pid = %d", pid1)
	}
	// The rendered config passes the real binary's own check.
	if err := validateSingboxConfig(bin, cfg.SingboxConfigPath); err != nil {
		t.Fatalf("real sing-box check on rendered config: %v", err)
	}
	// The V2Ray API answers on loopback (poll: the supervisor reports
	// running as soon as the process spawns, before it binds).
	waitFor(t, 5*time.Second, "v2ray api to answer", func() bool {
		_, err := querySingboxStats(defaultSingboxV2RayAddr)
		return err == nil
	})
	// A kill restarts it within 5 s (slice 5 acceptance).
	if err := syscall.Kill(pid1, syscall.SIGKILL); err != nil {
		t.Fatalf("kill pid %d: %v", pid1, err)
	}
	started := time.Now()
	waitFor(t, 5*time.Second, "sing-box to restart with a new pid", func() bool {
		st := sbSup.Status()
		return st.Running && st.PID != pid1 && st.PID > 0
	})
	if took := time.Since(started); took > 5*time.Second {
		t.Fatalf("restart took %s, want <= 5s", took)
	}
	// A config change restarts it within 5 s too.
	restarted := time.Now()
	doc2 := testSingboxDoc()
	doc2.ConfigVersion = 6
	doc2.Inbounds[0].Port = 34446 // move hy2
	if err := ap.applySingbox(doc2, xrayEmpty); err != nil {
		t.Fatalf("applySingbox #2: %v", err)
	}
	if took := time.Since(restarted); took > 5*time.Second {
		t.Fatalf("config-change restart took %s, want <= 5s", took)
	}
	if !sbSup.IsRunning() {
		t.Fatalf("sing-box not running after config change")
	}
	// Removing all sing-box inbounds stops it.
	doc3 := testSingboxDoc()
	doc3.ConfigVersion = 7
	for i := range doc3.Inbounds {
		if doc3.Inbounds[i].Protocol != "vless" {
			doc3.Inbounds[i].Enabled = false
		}
	}
	if err := ap.applySingbox(doc3, xrayEmpty); err != nil {
		t.Fatalf("applySingbox #3: %v", err)
	}
	waitFor(t, 5*time.Second, "sing-box to stop", func() bool { return !sbSup.IsRunning() })
}

// TestSingboxAnyTLSTrafficEndToEnd is the slice 5 acceptance proof
// for metering: a real sing-box AnyTLS client downloads a known-size
// file through the real sing-box server, and the reporter's next tick
// attributes the V2Ray API stats to the AnyTLS inbound row and to
// the per-user row, with an error far below the 5% acceptance bound.
// AnyTLS is used instead of HY2/TUIC because the sandbox blocks UDP
// (QUIC handshakes can never complete here); the metering code path
// is identical (all three inbounds write the user name into
// metadata.User). HY2/TUIC end-to-end stays a pilot acceptance item.
func TestSingboxAnyTLSTrafficEndToEnd(t *testing.T) {
	bin := realSingboxBin(t)
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")
	writeTestCert(t, certsDir, 1, "node.example.com")

	// --- Target: a local HTTP server serving a known-size payload. ---
	const payloadBytes = 5 << 20 // 5 MiB
	payload := make([]byte, payloadBytes)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	}))
	defer target.Close()

	// --- Server: one AnyTLS inbound only. ---
	cfg := &Config{
		XrayPath: "sleep", XrayConfigPath: filepath.Join(dir, "xray.json"),
		SingboxPath: bin, SingboxConfigPath: filepath.Join(dir, "sing-box.json"),
		APIPort: 10087, ControlAddr: "127.0.0.1:0",
	}
	xraySup := newSupervisor("sleep", cfg.XrayConfigPath)
	sbSup := newCoreSupervisor("sing-box", bin, cfg.SingboxConfigPath, "run", "-c", cfg.SingboxConfigPath)
	ap := newConfigApplier(cfg, xraySup, sbSup)
	defer sbSup.Stop()
	doc := &nodeConfig{
		OK: true, NodeID: 1, ConfigVersion: 5,
		Inbounds: []configInbound{
			{InboundTag: "anytls-443", Protocol: "anytls", Transport: "tcp", Security: "tls", Port: 34445, Listen: "127.0.0.1", SNI: "node.example.com", CertRef: 1, Enabled: true},
		},
		Users: []configUser{
			{UserID: "subuser:su-1", Kind: "subuser", ID: "su-1", Name: "u1", Email: "u-sub-su-1@node", VLESSUUID: "11111111-2222-3333-4444-555555555555"},
		},
	}
	if err := ap.applySingbox(doc, []byte(`{"inbounds":[]}`)); err != nil {
		t.Fatalf("applySingbox: %v", err)
	}
	waitFor(t, 5*time.Second, "sing-box server to start", sbSup.IsRunning)
	waitFor(t, 5*time.Second, "v2ray api to answer", func() bool {
		_, err := querySingboxStats(defaultSingboxV2RayAddr)
		return err == nil
	})

	// --- Client: sing-box with a SOCKS inbound and an AnyTLS outbound. ---
	// The server certificate is self-signed (test-only), so the
	// client skips verification; the server name still goes in SNI.
	clientCfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{
			map[string]any{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 11080},
		},
		"outbounds": []any{
			map[string]any{
				"type": "anytls", "tag": "anytls-out",
				"server": "127.0.0.1", "server_port": 34445,
				"password": "11111111-2222-3333-4444-555555555555",
				"tls":      map[string]any{"enabled": true, "server_name": "node.example.com", "insecure": true},
			},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "anytls-out"},
	}
	clientData, err := json.Marshal(clientCfg)
	if err != nil {
		t.Fatalf("encode client config: %v", err)
	}
	clientPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(clientPath, clientData, 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	if err := validateSingboxConfig(bin, clientPath); err != nil {
		t.Fatalf("client config check: %v", err)
	}
	clientCmd := exec.Command(bin, "run", "-c", clientPath)
	clientCmd.Stdout = nil
	clientCmd.Stderr = nil
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("start sing-box client: %v", err)
	}
	defer func() {
		_ = clientCmd.Process.Kill()
		_ = clientCmd.Wait()
	}()
	// Wait for the SOCKS port to accept.
	waitFor(t, 5*time.Second, "socks inbound to listen", func() bool {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:11080", 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})

	// --- Fake panel: captures the traffic report. ---
	var gotReport trafficReport
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/node/traffic" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotReport)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer panel.Close()
	repCfg := &Config{
		PanelURL: panel.URL, NodeID: 1,
		XrayPath: "sleep", XrayConfigPath: filepath.Join(dir, "xray.json"),
		SingboxPath: bin, SingboxConfigPath: filepath.Join(dir, "sing-box.json"),
		APIPort: 10087,
	}
	rep := newTrafficReporter(repCfg, panel.Client(), xraySup, sbSup, ap, &fakeStats{samples: []statsSample{{}}})
	// Tick 1 seeds the sing-box accumulator (no delta yet).
	if err := rep.tick(time.Now()); err != nil {
		t.Fatalf("tick 1: %v", err)
	}
	// Download 5 MiB through the tunnel (SOCKS -> AnyTLS -> direct).
	// env -u no_proxy -u NO_PROXY is REQUIRED: the sandbox sets
	// no_proxy=127.0.0.1, and curl bypasses --socks5 for loopback
	// targets when it is set, so without it the download never
	// touches sing-box at all (that bug once "proved" the Clash API
	// was dead; see build plan §9.4).
	fetch := exec.Command("env", "-u", "no_proxy", "-u", "NO_PROXY", "curl", "-sS", "--socks5-hostname", "127.0.0.1:11080", "-o", filepath.Join(dir, "got.bin"), target.URL)
	if out, err := fetch.CombinedOutput(); err != nil {
		t.Fatalf("curl through tunnel: %v: %s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(dir, "got.bin"))
	if err != nil {
		t.Fatalf("read fetched file: %v", err)
	}
	if len(got) != payloadBytes {
		t.Fatalf("fetched %d bytes, want %d", len(got), payloadBytes)
	}
	// Tick 2 reports the window covering the download.
	gotReport = trafficReport{}
	if err := rep.tick(time.Now()); err != nil {
		t.Fatalf("tick 2: %v", err)
	}
	if len(gotReport.Inbounds) != 1 || gotReport.Inbounds[0].InboundTag != "anytls-443" {
		t.Fatalf("report inbounds = %+v, want one anytls-443 row", gotReport.Inbounds)
	}
	row := gotReport.Inbounds[0]
	if row.Down <= 0 {
		t.Fatalf("anytls down = %d, want > 0", row.Down)
	}
	// Acceptance: V2Ray stats vs the client's actual download, <= 5%.
	diff := float64(row.Down - payloadBytes)
	if diff < 0 {
		diff = -diff
	}
	if errPct := diff / float64(payloadBytes); errPct > 0.05 {
		t.Fatalf("anytls down = %d vs fetched %d, error %.2f%%, want <= 5%%", row.Down, payloadBytes, errPct*100)
	}
	t.Logf("anytls-443 down=%d up=%d vs fetched=%d (error %.3f%%)", row.Down, row.Up, payloadBytes, diff/float64(payloadBytes)*100)
	// Per-user row: the same download attributed to su-1 by name.
	if len(gotReport.Users) != 1 || gotReport.Users[0].UserKey != "subuser:su-1" {
		t.Fatalf("report users = %+v, want one subuser:su-1 row", gotReport.Users)
	}
	urow := gotReport.Users[0]
	if urow.Down != row.Down || urow.Up != row.Up {
		t.Fatalf("user row = %+v, want the same counts as the inbound row %+v", urow, row)
	}
}

// on disk is skipped, not an error, and sing-box never starts.
func TestApplySingboxNoCertSkips(t *testing.T) {
	bin := realSingboxBin(t)
	dir := t.TempDir()
	cfg := &Config{
		XrayPath: "sleep", XrayConfigPath: filepath.Join(dir, "xray.json"),
		SingboxPath: bin, SingboxConfigPath: filepath.Join(dir, "sing-box.json"),
		APIPort: 10087, ControlAddr: "127.0.0.1:0",
	}
	xraySup := newSupervisor("sleep", cfg.XrayConfigPath)
	sbSup := newCoreSupervisor("sing-box", bin, cfg.SingboxConfigPath, "run", "-c", cfg.SingboxConfigPath)
	ap := newConfigApplier(cfg, xraySup, sbSup)
	defer sbSup.Stop()

	doc := testSingboxDoc() // CertRef 1, but no cert files on disk
	if err := ap.applySingbox(doc, []byte(`{"inbounds":[]}`)); err != nil {
		t.Fatalf("applySingbox without certs must not fail: %v", err)
	}
	if sbSup.IsRunning() {
		t.Fatalf("sing-box must not start when its inbounds have no certificates")
	}
	if tags := ap.singboxTags(); len(tags) != 0 {
		t.Fatalf("singboxTags = %v, want none", tags)
	}
}
