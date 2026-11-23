package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genECDSAKey returns a fresh P-256 private key.
func genECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return key
}

// pemEncodeCert returns PEM for a DER certificate.
func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// pemEncodeKey returns a PKCS#8 PEM for a private key.
func pemEncodeKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// genSelfSignedCert returns a self-signed P-256 cert/key pair (PEM).
// Used by join tests, where the agent only stores the pair.
func genSelfSignedCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key := genECDSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed cert: %v", err)
	}
	return pemEncodeCert(der), pemEncodeKey(t, key)
}

// genCA returns a CA certificate (PEM + parsed) and its key.
func genCA(t *testing.T) (caPEM []byte, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) {
	t.Helper()
	caKey = genECDSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return pemEncodeCert(der), caCert, caKey
}

// genSignedCert returns a cert/key pair signed by ca, for server or client use.
func genSignedCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, server bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key := genECDSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		// httptest TLS server serves on 127.0.0.1; add it as an IP SAN.
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create signed cert: %v", err)
	}
	return pemEncodeCert(der), pemEncodeKey(t, key)
}

// writeTestCertFiles writes cert/key PEM into dir and returns a Config
// pointing at them, for client tests.
func writeTestCertFiles(t *testing.T, dir string, certPEM, keyPEM []byte) *Config {
	t.Helper()
	certFile := filepath.Join(dir, "node.crt")
	keyFile := filepath.Join(dir, "node.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write test cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write test key: %v", err)
	}
	return &Config{PanelURL: "http://example.com:11111", NodeID: 1, CertFile: certFile, KeyFile: keyFile}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestJoinSuccess: stub panel accepts the token and returns a cert/key
// pair; join must write certs, key and config, all mode 0600.
func TestJoinSuccess(t *testing.T) {
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/node-backend/join" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		var req joinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode join request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.NodeID != 1 || req.Token != "join_11111111111111111111111111111111" {
			t.Errorf("unexpected join request: %+v", req)
			http.Error(w, "bad token", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(joinResponse{
			OK: true, NodeID: 1,
			ClientCertPEM: string(certPEM), ClientKeyPEM: string(keyPEM),
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := doJoin(srv.URL, "join_11111111111111111111111111111111", 1, false, dir); err != nil {
		t.Fatalf("doJoin: %v", err)
	}

	if got := fileMode(t, filepath.Join(dir, "certs", "node.crt")); got != 0o600 {
		t.Errorf("node.crt mode = %o, want 0600", got)
	}
	if got := fileMode(t, filepath.Join(dir, "certs", "node.key")); got != 0o600 {
		t.Errorf("node.key mode = %o, want 0600", got)
	}
	if got := fileMode(t, filepath.Join(dir, "config.json")); got != 0o600 {
		t.Errorf("config.json mode = %o, want 0600", got)
	}

	certData, _ := os.ReadFile(filepath.Join(dir, "certs", "node.crt"))
	if string(certData) != string(certPEM) {
		t.Errorf("node.crt content mismatch")
	}
	keyData, _ := os.ReadFile(filepath.Join(dir, "certs", "node.key"))
	if string(keyData) != string(keyPEM) {
		t.Errorf("node.key content mismatch")
	}

	cfg, err := loadConfig(dir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.PanelURL != srv.URL || cfg.NodeID != 1 || cfg.Insecure {
		t.Errorf("config mismatch: %+v", cfg)
	}
	if cfg.CertFile != filepath.Join(dir, "certs", "node.crt") || cfg.KeyFile != filepath.Join(dir, "certs", "node.key") {
		t.Errorf("config cert paths mismatch: %+v", cfg)
	}
}

// TestJoinBadToken: stub panel rejects the token with 400; join must
// fail and write no config or certs at all.
func TestJoinBadToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(joinResponse{OK: false, Error: "invalid or expired token"})
	}))
	defer srv.Close()

	dir := t.TempDir()
	err := doJoin(srv.URL, "join_00000000000000000000000000000000", 1, false, dir)
	if err == nil {
		t.Fatal("doJoin with bad token succeeded, want error")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(statErr) {
		t.Errorf("config.json was written despite failed join")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "certs", "node.crt")); !os.IsNotExist(statErr) {
		t.Errorf("node.crt was written despite failed join")
	}
}

// TestJoinNodeNotFound: 404 from the panel must also fail cleanly.
func TestJoinNodeNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(joinResponse{OK: false, Error: "node not found"})
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := doJoin(srv.URL, "join_11111111111111111111111111111111", 99, false, dir); err == nil {
		t.Fatal("doJoin with unknown node succeeded, want error")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(statErr) {
		t.Errorf("config.json was written despite failed join")
	}
}

// TestPull200: config pull returns a live config; version header and
// etag handling must be correct.
func TestPull200(t *testing.T) {
	var gotVersion, gotIfNoneMatch string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = r.Header.Get("X-Node-Backend-Version")
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodeConfig{
			OK: true, NodeID: 1, ConfigVersion: 3, ETag: `"v3"`,
			Inbounds: []configInbound{{InboundTag: "reality-443"}},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	status, nc, err := pullConfig(client, srv.URL, `"v2"`)
	if err != nil {
		t.Fatalf("pullConfig: %v", err)
	}
	if status != pullOK {
		t.Errorf("status = %q, want %q", status, pullOK)
	}
	if nc.ConfigVersion != 3 || nc.ETag != `"v3"` {
		t.Errorf("config = %+v, want version 3 etag \"v3\"", nc)
	}
	if gotVersion != Version {
		t.Errorf("X-Node-Backend-Version = %q, want %q", gotVersion, Version)
	}
	if gotIfNoneMatch != `"v2"` {
		t.Errorf("If-None-Match = %q, want %q", gotIfNoneMatch, `"v2"`)
	}
}

// TestPull304: unchanged config returns 304 with no body.
func TestPull304(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v3"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodeConfig{OK: true, NodeID: 1, ConfigVersion: 3, ETag: `"v3"`})
	}))
	defer srv.Close()

	dir := t.TempDir()
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	status, nc, err := pullConfig(client, srv.URL, `"v3"`)
	if err != nil {
		t.Fatalf("pullConfig: %v", err)
	}
	if status != pullNotModified {
		t.Errorf("status = %q, want %q", status, pullNotModified)
	}
	if nc != nil {
		t.Errorf("304 must return nil config, got %+v", nc)
	}
}

// TestPullDeleted: deleted=true means the node was removed on the panel.
func TestPullDeleted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodeConfig{
			OK: true, NodeID: 1, ConfigVersion: 0, ETag: `"deleted"`, Deleted: true,
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	status, nc, err := pullConfig(client, srv.URL, "")
	if err != nil {
		t.Fatalf("pullConfig: %v", err)
	}
	if status != pullDeleted {
		t.Errorf("status = %q, want %q", status, pullDeleted)
	}
	if nc == nil || !nc.Deleted {
		t.Errorf("config deleted flag missing: %+v", nc)
	}
}

// TestPullError: a 404 (unknown node) is an error, not a status.
func TestPullError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(nodeConfig{OK: false, Error: "unknown node"})
	}))
	defer srv.Close()

	dir := t.TempDir()
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	if _, _, err := pullConfig(client, srv.URL, ""); err == nil {
		t.Fatal("pullConfig with 404 succeeded, want error")
	}
}

// TestPullOnceStatePersistence: a 200 pull persists config_version,
// etag and a parseable RFC3339 last_pull to state.json; a later 304
// leaves the state untouched.
func TestPullOnceStatePersistence(t *testing.T) {
	etag := `"v7"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(nodeConfig{OK: true, NodeID: 1, ConfigVersion: 7, ETag: etag})
	}))
	defer srv.Close()

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	cfg.PanelURL = srv.URL
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}

	action, err := pullOnce(client, cfg, stateDir)
	if err != nil || action != actionContinue {
		t.Fatalf("pullOnce #1: action=%v err=%v", action, err)
	}
	st, err := loadState(stateDir)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if st.ConfigVersion != 7 || st.ETag != etag {
		t.Errorf("state = %+v, want version 7 etag %s", st, etag)
	}
	if _, err := time.Parse(time.RFC3339, st.LastPull); err != nil {
		t.Errorf("state last_pull %q is not RFC3339: %v", st.LastPull, err)
	}
	if got := fileMode(t, filepath.Join(stateDir, "state.json")); got != 0o600 {
		t.Errorf("state.json mode = %o, want 0600", got)
	}

	// Second pull: server answers 304, state must be unchanged.
	before, _ := os.ReadFile(filepath.Join(stateDir, "state.json"))
	action, err = pullOnce(client, cfg, stateDir)
	if err != nil || action != actionContinue {
		t.Fatalf("pullOnce #2: action=%v err=%v", action, err)
	}
	after, _ := os.ReadFile(filepath.Join(stateDir, "state.json"))
	if string(before) != string(after) {
		t.Errorf("304 pull changed state.json")
	}
}

// TestPullOnceDeleted: pullOnce reports actionDeleted for a deleted node.
func TestPullOnceDeleted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodeConfig{OK: true, NodeID: 1, ETag: `"deleted"`, Deleted: true})
	}))
	defer srv.Close()

	dir := t.TempDir()
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	cfg.PanelURL = srv.URL
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	action, err := pullOnce(client, cfg, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("pullOnce: %v", err)
	}
	if action != actionDeleted {
		t.Errorf("action = %v, want actionDeleted", action)
	}
}

// TestMTLS: end-to-end mTLS against a stub panel that requires and
// verifies a client certificate signed by the test CA.
func TestMTLS(t *testing.T) {
	caPEM, caCert, caKey := genCA(t)
	serverCertPEM, serverKeyPEM := genSignedCert(t, caCert, caKey, "panel", true)
	clientCertPEM, clientKeyPEM := genSignedCert(t, caCert, caKey, "node-1", false)

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("append CA cert to pool")
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Error("server saw no client certificate")
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		if r.TLS.PeerCertificates[0].Subject.CommonName != "node-1" {
			t.Errorf("client cert CN = %q, want node-1", r.TLS.PeerCertificates[0].Subject.CommonName)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodeConfig{OK: true, NodeID: 1, ConfigVersion: 1, ETag: `"v1"`})
	}))
	srvCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	cfg := writeTestCertFiles(t, dir, clientCertPEM, clientKeyPEM)
	cfg.PanelURL = srv.URL
	client, err := newHTTPClient(cfg, caPool)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	status, nc, err := pullConfig(client, srv.URL, "")
	if err != nil {
		t.Fatalf("pullConfig over mTLS: %v", err)
	}
	if status != pullOK || nc.ConfigVersion != 1 {
		t.Errorf("status=%q config=%+v, want ok version 1", status, nc)
	}
}

// TestVersionConstant pins the version string sent to the panel.
func TestVersionConstant(t *testing.T) {
	if Version != "0.1.3" {
		t.Errorf("Version = %q, want 0.1.3", Version)
	}
}
