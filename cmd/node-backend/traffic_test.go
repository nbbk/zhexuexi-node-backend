package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStats returns scripted QueryStats samples, one per call.
type fakeStats struct {
	mu      sync.Mutex
	samples []statsSample
	err     error
	calls   int
}

func (f *fakeStats) QueryStats(_ context.Context, _ string) (statsSample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.calls-1 < len(f.samples) {
		return f.samples[f.calls-1], nil
	}
	return f.samples[len(f.samples)-1], nil
}

// TestBuildReportContract: the POST body field names are the panel
// contract — check them exactly, including the health block and the
// empty online list (never null, never fabricated IPs).
func TestBuildReportContract(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		PanelURL: "http://example.com:11111", NodeID: 1,
		XrayPath: "/usr/local/bin/xray", XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10085, SpoolPath: filepath.Join(dir, "spool.json"),
	}
	sup := newSupervisor(cfg.XrayPath, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	users := effectiveUsers(testRealityDoc().Users)
	targets, err := vlessTargets(testRealityDoc())
	if err != nil {
		t.Fatalf("vlessTargets: %v", err)
	}
	ap.setApplied(12, users, byInboundSets(users, targets), targets, "deadbeef")

	rep := newTrafficReporter(cfg, nil, sup, nil, ap, nil)
	delta := statsDelta{
		users: map[string][2]int64{
			"u-sub-su-1@node":    {123, 456},
			"u-merged-ms-1@node": {0, 789},
			"u-sub-ghost@node":   {10, 20}, // not in the applied set: still reported
		},
		inbounds: map[string][2]int64{"reality-443": {123, 1245}},
	}
	got := rep.buildReport(time.Unix(1799999400, 0), time.Unix(1799999460, 0), delta, users, targets)
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	for _, key := range []string{"node_id", "window_start", "window_end", "users", "inbounds", "online", "health"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("report missing top-level field %q: %s", key, string(data))
		}
	}
	if m["node_id"] != float64(1) || m["window_start"] != float64(1799999400) || m["window_end"] != float64(1799999460) {
		t.Fatalf("report ids/windows wrong: %s", string(data))
	}
	health, ok := m["health"].(map[string]any)
	if !ok {
		t.Fatalf("health is not an object: %v", m["health"])
	}
	for _, key := range []string{"agent_version", "xray_version", "xray_running", "xray_restarts", "singbox_version", "singbox_running", "singbox_restarts", "config_version", "last_error", "cpu_percent", "mem_mb"} {
		if _, ok := health[key]; !ok {
			t.Fatalf("health missing field %q: %s", key, string(data))
		}
	}
	if health["agent_version"] != Version || health["xray_version"] != "26.11.9" || health["singbox_version"] != "1.14.4" {
		t.Fatalf("health versions wrong: %v", health)
	}
	if health["xray_running"] != false || health["xray_restarts"] != float64(0) || health["config_version"] != float64(12) {
		t.Fatalf("health state wrong: %v", health)
	}
	if health["last_error"] != "" {
		t.Fatalf("last_error = %q, want empty on a clean state", health["last_error"])
	}
	online, ok := m["online"].([]any)
	if !ok || len(online) != 0 {
		t.Fatalf("online must be an empty array, got %v", m["online"])
	}
	usersJSON, ok := m["users"].([]any)
	if !ok || len(usersJSON) != 3 {
		t.Fatalf("users = %v, want 3 rows", m["users"])
	}
	byKey := map[string]map[string]any{}
	for _, u := range usersJSON {
		row := u.(map[string]any)
		byKey[row["user_key"].(string)] = row
	}
	if byKey["subuser:su-1"]["up"] != float64(123) || byKey["subuser:su-1"]["down"] != float64(456) ||
		byKey["subuser:su-1"]["inbound_tag"] != "reality-443" {
		t.Fatalf("su-1 row wrong: %v", byKey["subuser:su-1"])
	}
	// A user assigned to all inbounds is attributed to the first
	// VLESS inbound in panel order (reality-443).
	if byKey["merged:ms-1"]["inbound_tag"] != "reality-443" {
		t.Fatalf("ms-1 row wrong: %v", byKey["merged:ms-1"])
	}
	// Unknown email: key derived from the email, never dropped.
	if byKey["subuser:ghost"]["up"] != float64(10) {
		t.Fatalf("ghost row wrong: %v", byKey["subuser:ghost"])
	}
	inbounds, ok := m["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("inbounds = %v, want 1 row", m["inbounds"])
	}
	row := inbounds[0].(map[string]any)
	if row["inbound_tag"] != "reality-443" || row["up"] != float64(123) || row["down"] != float64(1245) {
		t.Fatalf("inbound row wrong: %v", row)
	}
}

// TestAttributeInbound: single-assignment users get that inbound;
// unassigned users get the first VLESS inbound; users assigned
// only to non-Xray inbounds get "".
func TestAttributeInbound(t *testing.T) {
	targets := []vlessTarget{{Tag: "reality-443"}, {Tag: "xhttp-443"}}
	if got := attributeInbound(configUser{Inbounds: []string{"xhttp-443"}}, targets); got != "xhttp-443" {
		t.Fatalf("single assignment = %q, want xhttp-443", got)
	}
	if got := attributeInbound(configUser{}, targets); got != "reality-443" {
		t.Fatalf("no assignment = %q, want first target reality-443", got)
	}
	if got := attributeInbound(configUser{Inbounds: []string{"hy2-443"}}, targets); got != "" {
		t.Fatalf("non-Xray assignment = %q, want empty", got)
	}
	if got := attributeInbound(configUser{}, nil); got != "" {
		t.Fatalf("no targets = %q, want empty", got)
	}
}

// TestSpoolRoundTripAndPrune: spool save/load preserves windows at
// mode 0600; windows older than 24 h are pruned.
func TestSpoolRoundTripAndPrune(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spool.json")
	now := time.Now()
	windows := []trafficReport{
		{NodeID: 1, WindowStart: now.Add(-25 * time.Hour).Unix(), WindowEnd: now.Add(-25 * time.Hour).Unix()},
		{NodeID: 1, WindowStart: now.Add(-1 * time.Hour).Unix(), WindowEnd: now.Add(-59 * time.Minute).Unix()},
		{NodeID: 1, WindowStart: now.Add(-1 * time.Minute).Unix(), WindowEnd: now.Unix()},
		// Fresh zero-length window (same-second start/end): the
		// panel rejects it with 400, so it must be pruned too —
		// otherwise it poisons the spool and blocks every window
		// behind it (agent 0.1.5 startup race, fixed in 0.1.6).
		{NodeID: 1, WindowStart: now.Unix(), WindowEnd: now.Unix()},
	}
	if err := saveSpool(path, windows); err != nil {
		t.Fatalf("saveSpool: %v", err)
	}
	if got := fileMode(t, path); got != 0o600 {
		t.Fatalf("spool mode = %o, want 0600", got)
	}
	loaded, err := loadSpool(path)
	if err != nil {
		t.Fatalf("loadSpool: %v", err)
	}
	if len(loaded) != 4 {
		t.Fatalf("loaded %d windows, want 4", len(loaded))
	}
	kept, dropped := pruneSpool(loaded, now)
	if dropped != 2 || len(kept) != 2 {
		t.Fatalf("prune dropped=%d kept=%d, want 2 and 2", dropped, len(kept))
	}
	if kept[0].WindowEnd != windows[1].WindowEnd {
		t.Fatalf("prune kept the wrong windows: %+v", kept)
	}
	if got, err := loadSpool(filepath.Join(dir, "missing.json")); err != nil || len(got) != 0 {
		t.Fatalf("missing spool must load empty without error, got %v %v", got, err)
	}
	if err := persistSpool(path, nil); err != nil {
		t.Fatalf("persistSpool empty: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty spool must remove the file")
	}
}

// TestTickSkipsZeroLengthWindow: a tick in the same wall second as
// the window start must not post (window_start == window_end in
// unix seconds, which the panel rejects with 400). The window is
// kept open and the next tick reports the whole span. Regression
// test for the agent 0.1.5 startup race: the first tick ran in the
// same second as the reporter was built, the zero-length window
// went into the spool, and replay aborted on it every cycle.
func TestTickSkipsZeroLengthWindow(t *testing.T) {
	var mu sync.Mutex
	received := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/node/traffic" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		received++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()

	dir := t.TempDir()
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	cfg.PanelURL = srv.URL
	cfg.XrayPath = fakeBinary(t, "if [ \"$2\" = \"-test\" ]; then exit 0; fi\nsleep 300")
	cfg.XrayConfigPath = filepath.Join(dir, "xray.json")
	cfg.APIPort = 10085
	cfg.SpoolPath = filepath.Join(dir, "spool.json")
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	sup := newSupervisor(cfg.XrayPath, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	defer sup.Stop()
	doc := testRealityDoc()
	if err := ap.apply(doc); err != nil {
		t.Fatalf("apply doc: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)

	stats := &fakeStats{samples: []statsSample{{}}}
	rep := newTrafficReporter(cfg, client, sup, nil, ap, stats)
	rep.windowStart = time.Unix(1799999400, 0)

	// Tick in the same second as the window start: no post.
	if err := rep.tick(time.Unix(1799999400, 0)); err != nil {
		t.Fatalf("same-second tick should be skipped, got error: %v", err)
	}
	mu.Lock()
	got := received
	mu.Unlock()
	if got != 0 {
		t.Fatalf("same-second tick posted %d time(s), want 0", got)
	}
	if _, err := os.Stat(cfg.SpoolPath); !os.IsNotExist(err) {
		t.Fatalf("skipped tick must not create a spool file")
	}

	// Next tick 60 s later: one valid window is posted.
	if err := rep.tick(time.Unix(1799999460, 0)); err != nil {
		t.Fatalf("next tick should succeed: %v", err)
	}
	mu.Lock()
	got = received
	mu.Unlock()
	if got != 1 {
		t.Fatalf("panel received %d posts, want 1", got)
	}
	if _, err := os.Stat(cfg.SpoolPath); !os.IsNotExist(err) {
		t.Fatalf("spool file must not exist after a successful post")
	}
}

// TestReporterSpoolReplay: tick 1 fails to post (panel 500) and the
// window is spooled; tick 2 replays it oldest-first, then posts the
// current window, and the spool file is gone. The replayed window
// keeps its original window_start/window_end.
func TestReporterSpoolReplay(t *testing.T) {
	var mu sync.Mutex
	var received []trafficReport
	failFirst := 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/node/traffic" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Node-Backend-Version") != Version {
			t.Errorf("version header = %q, want %q", r.Header.Get("X-Node-Backend-Version"), Version)
		}
		var rep trafficReport
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			t.Errorf("decode traffic report: %v", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, rep)
		fail := len(received) <= failFirst
		mu.Unlock()
		if fail {
			http.Error(w, "panel down", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()

	dir := t.TempDir()
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	cfg.PanelURL = srv.URL
	cfg.XrayPath = fakeBinary(t, "if [ \"$2\" = \"-test\" ]; then exit 0; fi\nsleep 300")
	cfg.XrayConfigPath = filepath.Join(dir, "xray.json")
	cfg.APIPort = 10085
	cfg.SpoolPath = filepath.Join(dir, "spool.json")
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	sup := newSupervisor(cfg.XrayPath, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	defer sup.Stop()
	doc := testRealityDoc()
	if err := ap.apply(doc); err != nil {
		t.Fatalf("apply doc: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)

	stats := &fakeStats{samples: []statsSample{
		{"user>>>u-sub-su-1@node>>>traffic>>>uplink": 100,
			"user>>>u-sub-su-1@node>>>traffic>>>downlink": 200,
			"inbound>>>reality-443>>>traffic>>>uplink":    100,
			"inbound>>>reality-443>>>traffic>>>downlink":  200},
		{"user>>>u-sub-su-1@node>>>traffic>>>uplink": 300,
			"user>>>u-sub-su-1@node>>>traffic>>>downlink": 500,
			"inbound>>>reality-443>>>traffic>>>uplink":    300,
			"inbound>>>reality-443>>>traffic>>>downlink":  500},
	}}
	rep := newTrafficReporter(cfg, client, sup, nil, ap, stats)
	rep.windowStart = time.Unix(1799999400, 0)

	// Tick 1: baseline sample, no delta; the post fails (500).
	if err := rep.tick(time.Unix(1799999460, 0)); err == nil {
		t.Fatalf("tick 1 should fail (panel 500)")
	}
	if _, err := os.Stat(cfg.SpoolPath); err != nil {
		t.Fatalf("spool file must exist after a failed post: %v", err)
	}
	spooled, err := loadSpool(cfg.SpoolPath)
	if err != nil || len(spooled) != 1 {
		t.Fatalf("spool = %v err=%v, want 1 window", spooled, err)
	}
	if spooled[0].WindowStart != 1799999400 || spooled[0].WindowEnd != 1799999460 {
		t.Fatalf("spooled window = %d-%d, want 1799999400-1799999460",
			spooled[0].WindowStart, spooled[0].WindowEnd)
	}

	// Tick 2: replay the spooled window, then post the current one
	// (delta up 200 / down 300). Both must reach the panel.
	if err := rep.tick(time.Unix(1799999520, 0)); err != nil {
		t.Fatalf("tick 2 should succeed (replay + current): %v", err)
	}
	if _, err := os.Stat(cfg.SpoolPath); !os.IsNotExist(err) {
		t.Fatalf("spool file must be gone after a successful replay")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 3 {
		t.Fatalf("panel received %d posts, want 3 (failed w1, replayed w1, w2)", len(received))
	}
	if received[1].WindowStart != 1799999400 || received[1].WindowEnd != 1799999460 {
		t.Fatalf("replayed window = %d-%d, want the original 1799999400-1799999460",
			received[1].WindowStart, received[1].WindowEnd)
	}
	w2 := received[2]
	if w2.WindowStart != 1799999460 || w2.WindowEnd != 1799999520 {
		t.Fatalf("current window = %d-%d, want 1799999460-1799999520", w2.WindowStart, w2.WindowEnd)
	}
	if len(w2.Users) != 1 || w2.Users[0].UserKey != "subuser:su-1" ||
		w2.Users[0].Up != 200 || w2.Users[0].Down != 300 {
		t.Fatalf("w2 users = %+v, want one row subuser:su-1 up 200 down 300", w2.Users)
	}
	if len(w2.Inbounds) != 1 || w2.Inbounds[0].Up != 200 || w2.Inbounds[0].Down != 300 {
		t.Fatalf("w2 inbounds = %+v, want reality-443 up 200 down 300", w2.Inbounds)
	}
}

// TestReporterXrayDownReportsHealth: with Xray stopped the tick
// still posts a health-only report (xray_running=false) instead of
// failing the whole cycle — that is how the panel learns within
// 60 s that Xray stopped.
func TestReporterXrayDownReportsHealth(t *testing.T) {
	var mu sync.Mutex
	var received []trafficReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rep trafficReport
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			t.Errorf("decode traffic report: %v", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, rep)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()

	dir := t.TempDir()
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	cfg.PanelURL = srv.URL
	cfg.XrayPath = fakeBinary(t, "sleep 300")
	cfg.XrayConfigPath = filepath.Join(dir, "xray.json")
	cfg.APIPort = 10085
	cfg.SpoolPath = filepath.Join(dir, "spool.json")
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	sup := newSupervisor(cfg.XrayPath, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	defer sup.Stop()
	// Supervisor never started: Xray is down from the start.
	rep := newTrafficReporter(cfg, client, sup, nil, ap, &fakeStats{samples: []statsSample{{}}})
	// Tick a full minute after construction: a same-second tick is
	// skipped by design (zero-length window, 0.1.6), so the window
	// must span real time for the health-only report to go out.
	rep.windowStart = time.Now().Add(-time.Minute)
	if err := rep.tick(time.Now()); err != nil {
		t.Fatalf("tick with Xray down should still post health: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("panel received %d posts, want 1 health-only report", len(received))
	}
	h := received[0].Health
	if h.XrayRunning {
		t.Fatalf("health xray_running must be false, got %+v", h)
	}
	if len(received[0].Users) != 0 || len(received[0].Inbounds) != 0 {
		t.Fatalf("health-only report must carry no traffic rows: %+v", received[0])
	}
}

// TestHealthRestartsAndLastError: a supervisor bounce counts as one
// restart in health, and a failed apply surfaces as last_error
// until the next successful apply clears it.
func TestHealthRestartsAndLastError(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		XrayPath: fakeBinary(t, "if [ \"$2\" = \"-test\" ]; then exit 0; fi\nsleep 300"), XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10085, ControlAddr: "127.0.0.1:0",
		SpoolPath: filepath.Join(dir, "spool.json"),
	}
	sup := newSupervisor(cfg.XrayPath, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	defer sup.Stop()
	if err := sup.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	rep := newTrafficReporter(cfg, nil, sup, nil, ap, nil)
	if h := rep.buildHealth(); h.XrayRestarts != 0 || !h.XrayRunning {
		t.Fatalf("fresh health = %+v, want running with 0 restarts", h)
	}
	if err := sup.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if h := rep.buildHealth(); h.XrayRestarts != 1 {
		t.Fatalf("health after one bounce = %+v, want xray_restarts 1", h)
	}

	bad := testRealityDoc()
	bad.Inbounds[0].RealityPrivateKey = "" // render error
	if err := ap.apply(bad); err == nil {
		t.Fatalf("bad apply should fail")
	}
	if got := ap.lastError(); !strings.Contains(got, "private key") {
		t.Fatalf("lastError = %q, want the render error", got)
	}
	if h := rep.buildHealth(); !strings.Contains(h.LastError, "private key") {
		t.Fatalf("health last_error = %q, want the render error", h.LastError)
	}
	good := testRealityDoc()
	if err := ap.apply(good); err != nil {
		t.Fatalf("good apply: %v", err)
	}
	if got := ap.lastError(); got != "" {
		t.Fatalf("lastError = %q, want empty after a successful apply", got)
	}
}

// TestSampleProc: /proc reads return a real RSS (>0 MB) and a
// first-call CPU of 0 (no baseline yet).
func TestSampleProc(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{SpoolPath: filepath.Join(dir, "spool.json")}
	rep := newTrafficReporter(cfg, nil, newSupervisor("/usr/local/bin/xray", filepath.Join(dir, "xray.json")), nil, newConfigApplier(cfg, nil, nil), nil)
	cpu, mem := rep.sampleProc()
	if cpu != 0 {
		t.Fatalf("first cpu sample = %v, want 0 (no baseline)", cpu)
	}
	if mem <= 0 {
		t.Fatalf("mem = %v MB, want > 0 from /proc", mem)
	}
	// Second sample after some work: still sane numbers.
	sum := 0
	for i := 0; i < 1000000; i++ {
		sum += i
	}
	_ = sum
	time.Sleep(1100 * time.Millisecond)
	cpu, mem = rep.sampleProc()
	if cpu < 0 || mem <= 0 {
		t.Fatalf("second sample cpu=%v mem=%v, want cpu >= 0 and mem > 0", cpu, mem)
	}
}

// TestLoadConfigSpoolDefault: spool_path defaults to
// <config-dir>/spool.json; an explicit value wins.
func TestLoadConfigSpoolDefault(t *testing.T) {
	dir := t.TempDir()
	oldJSON := `{"panel_url":"https://example.com:11111","node_id":1,` +
		`"cert_file":"/etc/node-backend/certs/node.crt","key_file":"/etc/node-backend/certs/node.key"}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(oldJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := loadConfig(dir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.SpoolPath != filepath.Join(dir, "spool.json") {
		t.Fatalf("spool path = %q, want <config-dir>/spool.json", cfg.SpoolPath)
	}

	dir2 := t.TempDir()
	newJSON := `{"panel_url":"https://example.com:11111","node_id":1,` +
		`"cert_file":"/etc/node-backend/certs/node.crt","key_file":"/etc/node-backend/certs/node.key",` +
		`"spool_path":"/var/lib/node-backend/spool.json"}`
	if err := os.WriteFile(filepath.Join(dir2, "config.json"), []byte(newJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg2, err := loadConfig(dir2)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg2.SpoolPath != "/var/lib/node-backend/spool.json" {
		t.Fatalf("explicit spool path lost: %q", cfg2.SpoolPath)
	}
}
