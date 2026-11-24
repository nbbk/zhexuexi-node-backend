package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Certificate delivery and renewal (slice 7): the panel ships
// certificates in the config doc (nodeConfig.Certs), the agent
// writes them to <config-dir>/certs/<ref>.crt/.key (0600, atomic),
// and a content change reloads the core that serves the inbound —
// even though the rendered config is byte-identical (it references
// certificate files by path, not by content).

// makeTestCertPEM generates a fresh self-signed certificate for
// domain and returns the PEM bodies (unlike writeTestCert, it does
// not write files: the caller delivers the PEM through nodeConfig,
// as the panel does).
func makeTestCertPEM(t *testing.T, domain string) (crt, key string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	crt = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	key = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	return crt, key
}

// testCertApplier builds an applier whose certs land in dir/certs.
// The supervisors are nil: syncCerts and the renderers do not need
// them, and the reload tests build their own applier.
func testCertApplier(dir string) *configApplier {
	cfg := &Config{
		XrayPath: "xray", XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10085, ControlAddr: "127.0.0.1:0",
	}
	return newConfigApplier(cfg, nil, nil)
}

// TestNodeConfigCertsJSON: the panel's certs array decodes into
// configCert with JSON field names ref/crt/key (slice 7 contract).
func TestNodeConfigCertsJSON(t *testing.T) {
	var nc nodeConfig
	body := `{"ok":true,"node_id":1,"config_version":3,"etag":"\"v3\"",
		"certs":[{"ref":7,"crt":"---CRT---","key":"---KEY---"}]}`
	if err := json.Unmarshal([]byte(body), &nc); err != nil {
		t.Fatalf("unmarshal nodeConfig: %v", err)
	}
	if len(nc.Certs) != 1 || nc.Certs[0].Ref != 7 ||
		nc.Certs[0].Crt != "---CRT---" || nc.Certs[0].Key != "---KEY---" {
		t.Fatalf("certs = %+v, want [{7 ---CRT--- ---KEY---}]", nc.Certs)
	}
}

// TestSyncCertsWrites0600AndIdempotent: a delivered certificate is
// written 0600 with the exact PEM content; a second sync of the
// same content writes nothing (modtime unchanged, changed empty).
func TestSyncCertsWrites0600AndIdempotent(t *testing.T) {
	dir := t.TempDir()
	ap := testCertApplier(dir)
	crt, key := makeTestCertPEM(t, "node.example.com")
	doc := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 1,
		Certs: []configCert{{Ref: 7, Crt: crt, Key: key}}}

	changed, err := ap.syncCerts(doc)
	if err != nil {
		t.Fatalf("syncCerts: %v", err)
	}
	if !changed[7] {
		t.Fatalf("changed = %v, want ref 7 reported", changed)
	}
	for _, f := range []struct {
		path string
		want string
	}{
		{filepath.Join(dir, "certs", "7.crt"), crt},
		{filepath.Join(dir, "certs", "7.key"), key},
	} {
		st, err := os.Stat(f.path)
		if err != nil {
			t.Fatalf("stat %s: %v", f.path, err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", f.path, st.Mode().Perm())
		}
		got, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("read %s: %v", f.path, err)
		}
		if string(got) != f.want {
			t.Fatalf("%s content mismatch", f.path)
		}
	}
	crtInfo, _ := os.Stat(filepath.Join(dir, "certs", "7.crt"))
	changed, err = ap.syncCerts(doc)
	if err != nil {
		t.Fatalf("syncCerts #2: %v", err)
	}
	if len(changed) != 0 {
		t.Fatalf("changed on identical re-sync = %v, want empty", changed)
	}
	if after, _ := os.Stat(filepath.Join(dir, "certs", "7.crt")); !after.ModTime().Equal(crtInfo.ModTime()) {
		t.Fatalf("identical re-sync rewrote 7.crt")
	}
}

// TestSyncCertsRenewalReplacesContent: a new PEM for the same ref
// replaces the files on disk and is reported as changed.
func TestSyncCertsRenewalReplacesContent(t *testing.T) {
	dir := t.TempDir()
	ap := testCertApplier(dir)
	crtA, keyA := makeTestCertPEM(t, "node.example.com")
	crtB, keyB := makeTestCertPEM(t, "node.example.com")
	if crtA == crtB {
		t.Fatalf("test certs must differ")
	}
	doc := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 1,
		Certs: []configCert{{Ref: 7, Crt: crtA, Key: keyA}}}
	if _, err := ap.syncCerts(doc); err != nil {
		t.Fatalf("syncCerts #1: %v", err)
	}
	doc.ConfigVersion = 2
	doc.Certs = []configCert{{Ref: 7, Crt: crtB, Key: keyB}}
	changed, err := ap.syncCerts(doc)
	if err != nil {
		t.Fatalf("syncCerts #2: %v", err)
	}
	if !changed[7] {
		t.Fatalf("changed = %v, want ref 7 reported", changed)
	}
	got, err := os.ReadFile(filepath.Join(dir, "certs", "7.crt"))
	if err != nil {
		t.Fatalf("read 7.crt: %v", err)
	}
	if string(got) != crtB {
		t.Fatalf("7.crt was not replaced with the renewed certificate")
	}
}

// TestSyncCertsRejectsBadPair: a crt/key mismatch (or garbage PEM)
// aborts the sync and leaves any previously delivered files
// untouched — the running cores keep serving the old certificate.
func TestSyncCertsRejectsBadPair(t *testing.T) {
	dir := t.TempDir()
	ap := testCertApplier(dir)
	crtA, keyA := makeTestCertPEM(t, "node.example.com")
	_, keyB := makeTestCertPEM(t, "node.example.com")
	good := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 1,
		Certs: []configCert{{Ref: 7, Crt: crtA, Key: keyA}}}
	if _, err := ap.syncCerts(good); err != nil {
		t.Fatalf("syncCerts good: %v", err)
	}
	bad := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 2,
		Certs: []configCert{{Ref: 7, Crt: crtA, Key: keyB}}}
	if _, err := ap.syncCerts(bad); err == nil || !strings.Contains(err.Error(), "ref 7") {
		t.Fatalf("mismatched pair should error with the ref, got %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "certs", "7.crt"))
	if err != nil || string(got) != crtA {
		t.Fatalf("bad sync must leave 7.crt untouched, got %q err %v", got, err)
	}
	// An empty crt/key entry is ignored (logged), not an error, and
	// writes nothing — a partial panel delivery must not fail the
	// whole apply.
	empty := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 3,
		Certs: []configCert{{Ref: 8, Crt: "", Key: ""}}}
	if changed, err := ap.syncCerts(empty); err != nil || len(changed) != 0 {
		t.Fatalf("empty cert entry: changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "certs", "8.crt")); !os.IsNotExist(err) {
		t.Fatalf("empty cert entry must not write 8.crt")
	}
}

// TestSyncCertsLeavesStaleFiles: a certificate that is no longer
// referenced stays on disk (never loaded by either core, and an
// empty certs list from an older panel must not wipe delivered
// certificates).
func TestSyncCertsLeavesStaleFiles(t *testing.T) {
	dir := t.TempDir()
	ap := testCertApplier(dir)
	crt, key := makeTestCertPEM(t, "node.example.com")
	doc := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 1,
		Certs: []configCert{{Ref: 7, Crt: crt, Key: key}}}
	if _, err := ap.syncCerts(doc); err != nil {
		t.Fatalf("syncCerts: %v", err)
	}
	empty := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 2}
	if changed, err := ap.syncCerts(empty); err != nil || len(changed) != 0 {
		t.Fatalf("empty sync: changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "certs", "7.crt")); err != nil {
		t.Fatalf("unreferenced 7.crt must be left on disk: %v", err)
	}
}

// TestRenderXrayTLSInbound: a VLESS TCP+TLS inbound with its
// certificate on disk renders tlsSettings with the certificate file
// paths and the SNI as serverName; without the file it is skipped
// (needsCert), never rendered without a certificate.
func TestRenderXrayTLSInbound(t *testing.T) {
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")
	writeTestCert(t, certsDir, 7, "node.example.com")
	doc := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 1,
		Inbounds: []configInbound{
			{InboundTag: "tls-443", Protocol: "vless", Transport: "tcp",
				Security: "tls", Port: 8443, SNI: "node.example.com",
				CertRef: 7, Flow: "xtls-rprx-vision", Enabled: true},
		},
		Users: testRealityDoc().Users,
	}
	data, _, _, needsCert, err := renderXrayConfig(doc, 10085, certsDir)
	if err != nil {
		t.Fatalf("renderXrayConfig: %v", err)
	}
	if len(needsCert) != 0 {
		t.Fatalf("needsCert = %v, want none", needsCert)
	}
	p := parseXrayJSON(t, data)
	in := p.inboundByTag(t, "tls-443")
	if in["protocol"] != "vless" || in["port"] != float64(8443) {
		t.Fatalf("tls inbound wrong: %v", in)
	}
	ss := strMap(t, in["streamSettings"])
	if ss["network"] != "tcp" || ss["security"] != "tls" {
		t.Fatalf("tls streamSettings wrong: %v", ss)
	}
	tlsSettings := strMap(t, ss["tlsSettings"])
	if tlsSettings["serverName"] != "node.example.com" {
		t.Fatalf("serverName = %v, want node.example.com", tlsSettings["serverName"])
	}
	certs, _ := tlsSettings["certificates"].([]any)
	if len(certs) != 1 {
		t.Fatalf("certificates = %v, want one entry", tlsSettings["certificates"])
	}
	c0 := strMap(t, certs[0])
	if c0["certificateFile"] != filepath.Join(certsDir, "7.crt") ||
		c0["keyFile"] != filepath.Join(certsDir, "7.key") {
		t.Fatalf("certificate files wrong: %v", c0)
	}
	clients, _ := strMap(t, in["settings"])["clients"].([]any)
	if len(clients) != 2 || strMap(t, clients[0])["flow"] != "xtls-rprx-vision" {
		t.Fatalf("tls clients wrong: %v", clients)
	}

	// No certificate on disk: skipped, not rendered, not an error.
	data, _, _, needsCert, err = renderXrayConfig(doc, 10085, filepath.Join(dir, "no-certs"))
	if err != nil {
		t.Fatalf("renderXrayConfig without certs: %v", err)
	}
	if len(needsCert) != 1 || needsCert[0] != "tls-443" {
		t.Fatalf("needsCert = %v, want [tls-443]", needsCert)
	}
	p = parseXrayJSON(t, data)
	if len(p.inbounds(t)) != 1 {
		t.Fatalf("rendered %d inbounds, want 1 (api only)", len(p.inbounds(t)))
	}
}

// TestRenderTrojanInbound: a Trojan TCP+TLS inbound with its
// certificate on disk renders with the certificate file paths and
// one client per user (password = the user's UUID); without the
// file it is skipped (needsCert); a non-TLS Trojan is skipped.
func TestRenderTrojanInbound(t *testing.T) {
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")
	writeTestCert(t, certsDir, 7, "node.example.com")
	doc := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 1,
		Inbounds: []configInbound{
			{InboundTag: "trojan-443", Protocol: "trojan", Transport: "tcp",
				Security: "tls", Port: 8443, SNI: "node.example.com",
				CertRef: 7, Enabled: true},
		},
		Users: testRealityDoc().Users,
	}
	data, _, _, needsCert, err := renderXrayConfig(doc, 10085, certsDir)
	if err != nil {
		t.Fatalf("renderXrayConfig: %v", err)
	}
	if len(needsCert) != 0 {
		t.Fatalf("needsCert = %v, want none", needsCert)
	}
	p := parseXrayJSON(t, data)
	in := p.inboundByTag(t, "trojan-443")
	if in["protocol"] != "trojan" || in["port"] != float64(8443) {
		t.Fatalf("trojan inbound wrong: %v", in)
	}
	ss := strMap(t, in["streamSettings"])
	if ss["network"] != "tcp" || ss["security"] != "tls" {
		t.Fatalf("trojan streamSettings wrong: %v", ss)
	}
	tlsSettings := strMap(t, ss["tlsSettings"])
	if tlsSettings["serverName"] != "node.example.com" {
		t.Fatalf("serverName = %v, want node.example.com", tlsSettings["serverName"])
	}
	certs, _ := tlsSettings["certificates"].([]any)
	if len(certs) != 1 {
		t.Fatalf("certificates = %v, want one entry", tlsSettings["certificates"])
	}
	c0 := strMap(t, certs[0])
	if c0["certificateFile"] != filepath.Join(certsDir, "7.crt") ||
		c0["keyFile"] != filepath.Join(certsDir, "7.key") {
		t.Fatalf("certificate files wrong: %v", c0)
	}
	clients, _ := strMap(t, in["settings"])["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("trojan clients = %d, want 2", len(clients))
	}
	c0 = strMap(t, clients[0])
	if c0["password"] != "11111111-2222-3333-4444-555555555555" ||
		c0["email"] != "u-sub-su-1@node" {
		t.Fatalf("trojan client wrong: %v", c0)
	}

	// No certificate on disk: needsCert skip.
	_, _, _, needsCert, err = renderXrayConfig(doc, 10085, filepath.Join(dir, "no-certs"))
	if err != nil {
		t.Fatalf("renderXrayConfig without certs: %v", err)
	}
	if len(needsCert) != 1 || needsCert[0] != "trojan-443" {
		t.Fatalf("needsCert = %v, want [trojan-443]", needsCert)
	}

	// Non-TLS Trojan is skipped (plain, no camouflage).
	doc.Inbounds[0].Security = "none"
	data, _, skipped, _, err := renderXrayConfig(doc, 10085, certsDir)
	if err != nil {
		t.Fatalf("renderXrayConfig: %v", err)
	}
	if len(skipped) != 1 || skipped[0] != "trojan-443" {
		t.Fatalf("skipped = %v, want [trojan-443]", skipped)
	}
	p = parseXrayJSON(t, data)
	if len(p.inbounds(t)) != 1 {
		t.Fatalf("rendered %d inbounds, want 1 (api only)", len(p.inbounds(t)))
	}
}

// testTLSApplyDoc builds a panel config with a single VLESS TLS
// inbound (loopback port, so the real Xray can bind it in tests)
// and the certificate delivered in the config doc, as the panel
// ships it in slice 7.
func testTLSApplyDoc(crt, key string, version int) *nodeConfig {
	return &nodeConfig{OK: true, NodeID: 1, ConfigVersion: version,
		Inbounds: []configInbound{
			{InboundTag: "tls-443", Protocol: "vless", Transport: "tcp",
				Security: "tls", Port: 24443, Listen: "127.0.0.1",
				SNI: "node.example.com", CertRef: 7,
				Flow: "xtls-rprx-vision", Enabled: true},
		},
		Users: testRealityDoc().Users,
		Certs: []configCert{{Ref: 7, Crt: crt, Key: key}},
	}
}

// TestApplyCertRenewalRestartsXray is the slice 7 renewal
// acceptance for the Xray side: the panel delivers a certificate,
// the agent applies it; the panel then delivers a renewed
// certificate for the same ref with the inbounds unchanged, and the
// agent must restart Xray (new pid) within the same apply, even
// though the rendered config is byte-identical.
func TestApplyCertRenewalRestartsXray(t *testing.T) {
	xrayBin := realXrayBin(t)
	dir := t.TempDir()
	cfg := &Config{
		XrayPath: xrayBin, XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10088, ControlAddr: "127.0.0.1:0",
	}
	sup := newSupervisor(xrayBin, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	defer sup.Stop()

	crtA, keyA := makeTestCertPEM(t, "node.example.com")
	crtB, keyB := makeTestCertPEM(t, "node.example.com")
	if err := ap.apply(testTLSApplyDoc(crtA, keyA, 1)); err != nil {
		t.Fatalf("apply #1: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	pid1 := sup.Status().PID
	if pid1 <= 0 {
		t.Fatalf("pid = %d", pid1)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "certs", "7.crt")); err != nil || string(got) != crtA {
		t.Fatalf("7.crt after apply #1 = %q err %v", got, err)
	}
	// Same inbounds, renewed certificate: Xray must restart.
	if err := ap.apply(testTLSApplyDoc(crtB, keyB, 2)); err != nil {
		t.Fatalf("apply #2 (renewal): %v", err)
	}
	waitFor(t, 5*time.Second, "xray to restart with a new pid", func() bool {
		st := sup.Status()
		return st.Running && st.PID != pid1 && st.PID > 0
	})
	if got, err := os.ReadFile(filepath.Join(dir, "certs", "7.crt")); err != nil || string(got) != crtB {
		t.Fatalf("7.crt after renewal = %q err %v", got, err)
	}
	if ap.appliedVersion() != 2 {
		t.Fatalf("applied version = %d, want 2", ap.appliedVersion())
	}
}

// TestApplyCertRenewalRestartsSingbox is the slice 7 renewal
// acceptance for the sing-box side: same shape as the Xray test —
// a renewed certificate for the same ref, inbounds unchanged, must
// restart sing-box (new pid) in the same apply.
func TestApplyCertRenewalRestartsSingbox(t *testing.T) {
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

	crtA, keyA := makeTestCertPEM(t, "node.example.com")
	crtB, keyB := makeTestCertPEM(t, "node.example.com")
	xrayEmpty := []byte(`{"inbounds":[]}`)

	apply := func(crt, key string, version int) {
		t.Helper()
		doc := testSingboxDoc()
		doc.ConfigVersion = version
		doc.Certs = []configCert{{Ref: 1, Crt: crt, Key: key}}
		changed, err := ap.syncCerts(doc)
		if err != nil {
			t.Fatalf("syncCerts: %v", err)
		}
		if err := ap.applySingbox(doc, xrayEmpty,
			certChangeAffects(changed, singboxTLSRefs(doc))); err != nil {
			t.Fatalf("applySingbox: %v", err)
		}
	}
	apply(crtA, keyA, 5)
	waitFor(t, 5*time.Second, "sing-box to start", sbSup.IsRunning)
	pid1 := sbSup.Status().PID
	if pid1 <= 0 {
		t.Fatalf("pid = %d", pid1)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "certs", "1.crt")); err != nil || string(got) != crtA {
		t.Fatalf("1.crt after apply #1 = %q err %v", got, err)
	}
	// Same inbounds, renewed certificate: sing-box must restart.
	apply(crtB, keyB, 6)
	waitFor(t, 5*time.Second, "sing-box to restart with a new pid", func() bool {
		st := sbSup.Status()
		return st.Running && st.PID != pid1 && st.PID > 0
	})
	if got, err := os.ReadFile(filepath.Join(dir, "certs", "1.crt")); err != nil || string(got) != crtB {
		t.Fatalf("1.crt after renewal = %q err %v", got, err)
	}
}
