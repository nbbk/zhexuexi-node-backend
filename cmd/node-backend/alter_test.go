package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeAlter records AlterInbound calls for apply tests.
type fakeAlterCall struct {
	tag    string
	users  []alterUser
	emails []string
}

type fakeAlter struct {
	adds    []fakeAlterCall
	removes []fakeAlterCall
	err     error
}

func (f *fakeAlter) AddUsers(_ context.Context, _ string, target vlessTarget, users []alterUser) error {
	if f.err != nil {
		return f.err
	}
	f.adds = append(f.adds, fakeAlterCall{tag: target.Tag, users: users})
	return nil
}

func (f *fakeAlter) RemoveUsers(_ context.Context, _ string, target vlessTarget, emails []string) error {
	if f.err != nil {
		return f.err
	}
	f.removes = append(f.removes, fakeAlterCall{tag: target.Tag, emails: emails})
	return nil
}

func emailSet(users []alterUser) map[string]bool {
	out := map[string]bool{}
	for _, u := range users {
		out[u.Email] = true
	}
	return out
}

// TestDiffUsers: add / remove / rotate are distinguished by email;
// a UUID change under the same email is a rotation (remove + add).
func TestDiffUsers(t *testing.T) {
	old := map[string]configUser{
		"a@node": {Email: "a@node", VLESSUUID: "11111111-2222-3333-4444-555555555555"},
		"b@node": {Email: "b@node", VLESSUUID: "22222222-3333-4444-5555-666666666666"},
		"c@node": {Email: "c@node", VLESSUUID: "33333333-4444-5555-6666-777777777777"},
	}
	new := map[string]configUser{
		"a@node": {Email: "a@node", VLESSUUID: "11111111-2222-3333-4444-555555555555"},
		"b@node": {Email: "b@node", VLESSUUID: "99999999-8888-7777-6666-555555555555"},
		"d@node": {Email: "d@node", VLESSUUID: "44444444-5555-6666-7777-888888888888"},
	}
	d := diffUsers(old, new)
	if len(d.added) != 1 || d.added[0].Email != "d@node" {
		t.Fatalf("added = %v, want [d@node]", d.added)
	}
	if len(d.rotated) != 1 || d.rotated[0].Email != "b@node" ||
		d.rotated[0].VLESSUUID != "99999999-8888-7777-6666-555555555555" {
		t.Fatalf("rotated = %v, want [b@node with new uuid]", d.rotated)
	}
	removed := map[string]bool{}
	for _, e := range d.removed {
		removed[e] = true
	}
	if !removed["b@node"] || !removed["c@node"] || len(removed) != 2 {
		t.Fatalf("removed = %v, want [b@node c@node]", d.removed)
	}
	if len(diffUsers(old, old).added) != 0 || len(diffUsers(old, old).removed) != 0 {
		t.Fatalf("identical sets must diff empty")
	}
}

// TestEffectiveUsers: disabled users and users without a UUID never
// reach Xray (same filter as vlessClients).
func TestEffectiveUsers(t *testing.T) {
	users := []configUser{
		{Email: "a@node", VLESSUUID: "11111111-2222-3333-4444-555555555555"},
		{Email: "b@node", VLESSUUID: "22222222-3333-4444-5555-666666666666", Disabled: true},
		{Email: "c@node", VLESSUUID: ""},
	}
	got := effectiveUsers(users)
	if len(got) != 1 || got["a@node"].VLESSUUID == "" {
		t.Fatalf("effective = %v, want only a@node", got)
	}
}

// TestVlessTargets: reality inbounds carry their flow, xhttp
// inbounds carry none, non-VLESS inbounds are not targets.
func TestVlessTargets(t *testing.T) {
	targets, err := vlessTargets(testRealityDoc(), "")
	if err != nil {
		t.Fatalf("vlessTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %v, want reality-443 + xhttp-443", targets)
	}
	byTag := map[string]vlessTarget{}
	for _, tg := range targets {
		byTag[tg.Tag] = tg
	}
	if byTag["reality-443"].Flow != "xtls-rprx-vision" || byTag["reality-443"].Port != 443 {
		t.Fatalf("reality target wrong: %+v", byTag["reality-443"])
	}
	if byTag["xhttp-443"].Flow != "" || byTag["xhttp-443"].Port != 8443 {
		t.Fatalf("xhttp target must carry no flow: %+v", byTag["xhttp-443"])
	}
}

// TestUsersAndStructureFromRendered: the disk seed round-trips — the
// users come back, and the stripped structure SHA is identical
// whether the render carried users or not.
func TestUsersAndStructureFromRendered(t *testing.T) {
	doc := testRealityDoc()
	data, _, _, _, err := renderXrayConfig(doc, 10085, "")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	users, byInbound, structure, err := usersAndStructureFromRendered(data)
	if err != nil {
		t.Fatalf("seed parse: %v", err)
	}
	if len(users) != 2 || users["u-sub-su-1@node"].VLESSUUID != "11111111-2222-3333-4444-555555555555" ||
		users["u-merged-ms-1@node"].VLESSUUID != "22222222-3333-4444-5555-666666666666" {
		t.Fatalf("seeded users = %v, want the two rendered users", users)
	}
	// Slice 4: the disk seed also splits users per inbound (both
	// users are assigned to both VLESS inbounds here).
	if len(byInbound) != 2 || len(byInbound["reality-443"]) != 2 || len(byInbound["xhttp-443"]) != 2 {
		t.Fatalf("seeded per-inbound users = %v, want 2 users in each of reality-443 and xhttp-443", byInbound)
	}
	if byInbound["reality-443"]["u-sub-su-1@node"].VLESSUUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("seeded reality-443 users wrong: %v", byInbound["reality-443"])
	}
	noUsers := &nodeConfig{OK: true, NodeID: 1, ConfigVersion: 2, Inbounds: doc.Inbounds}
	emptyData, _, _, _, err := renderXrayConfig(noUsers, 10085, "")
	if err != nil {
		t.Fatalf("render without users: %v", err)
	}
	emptyStructure, err := structureSHA(emptyData)
	if err != nil {
		t.Fatalf("structure sha: %v", err)
	}
	if structure != emptyStructure {
		t.Fatalf("structure sha differs with/without users: %s vs %s", structure, emptyStructure)
	}
	// A structural change (port) must change the structure SHA.
	doc2 := testRealityDoc()
	doc2.Inbounds[0].Port = 444
	data2, _, _, _, err := renderXrayConfig(doc2, 10085, "")
	if err != nil {
		t.Fatalf("render changed doc: %v", err)
	}
	structure2, err := structureSHA(data2)
	if err != nil {
		t.Fatalf("structure sha #2: %v", err)
	}
	if structure2 == structure {
		t.Fatalf("port change did not change the structure sha")
	}
}

// testRealXrayDoc renders the default trio on loopback test ports.
func testRealXrayDoc(apiPort, realityPort, xhttpPort int) *nodeConfig {
	doc := testRealityDoc()
	doc.Inbounds[0].Port = realityPort
	doc.Inbounds[0].Listen = "127.0.0.1"
	doc.Inbounds[1].Port = xhttpPort
	doc.Inbounds[1].Listen = "127.0.0.1"
	doc.ConfigVersion = 2
	return doc
}

func realXrayBin(t *testing.T) string {
	t.Helper()
	xrayBin := os.Getenv("XRAY_BIN")
	if xrayBin == "" {
		xrayBin = filepath.Join(os.Getenv("HOME"), "workspace", "toolchains", "xray", "xray")
	}
	if _, err := os.Stat(xrayBin); err != nil {
		t.Skipf("no xray binary at %s", xrayBin)
	}
	return xrayBin
}

// TestApplyUsersOnlyHotPath: a user-only change must go through the
// fake AlterInbound client, leave xray.json untouched and keep the
// Xray PID.
func TestApplyUsersOnlyHotPath(t *testing.T) {
	xrayBin := realXrayBin(t)
	dir := t.TempDir()
	cfg := &Config{
		XrayPath: xrayBin, XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10086, ControlAddr: "127.0.0.1:0",
	}
	sup := newSupervisor(xrayBin, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	fake := &fakeAlter{}
	ap.alter = fake
	defer sup.Stop()

	doc := testRealXrayDoc(10086, 24444, 28444)
	if err := ap.apply(doc); err != nil {
		t.Fatalf("apply #1: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	pid1 := sup.Status().PID
	before, err := os.ReadFile(cfg.XrayConfigPath)
	if err != nil {
		t.Fatalf("read xray.json: %v", err)
	}

	// v3: add u3, rotate u2's UUID, keep u1.
	doc3 := testRealXrayDoc(10086, 24444, 28444)
	doc3.ConfigVersion = 3
	doc3.Users[1].VLESSUUID = "99999999-8888-7777-6666-555555555555"
	doc3.Users = append(doc3.Users, configUser{
		UserID: "subuser:su-3", Kind: "subuser", ID: "su-3", Name: "u3",
		Email: "u-sub-su-3@node", VLESSUUID: "33333333-4444-5555-6666-777777777777",
	})
	if err := ap.apply(doc3); err != nil {
		t.Fatalf("apply #2 (users only): %v", err)
	}
	if pid := sup.Status().PID; pid != pid1 {
		t.Fatalf("user-only change restarted xray: %d -> %d", pid1, pid)
	}
	// Slice 4: a hot apply now also writes the rendered config to
	// disk, so the disk file agrees with the running Xray (the
	// 0.1.3 bug was exactly that it did not). The file must now
	// carry the new user and the rotated UUID.
	after, err := os.ReadFile(cfg.XrayConfigPath)
	if err != nil {
		t.Fatalf("read xray.json after: %v", err)
	}
	if string(before) == string(after) {
		t.Fatalf("user-only change left xray.json untouched; disk must follow the hot apply")
	}
	if !strings.Contains(string(after), "33333333-4444-5555-6666-777777777777") ||
		!strings.Contains(string(after), "99999999-8888-7777-6666-555555555555") {
		t.Fatalf("xray.json after hot apply lacks the new/rotated user:\n%s", string(after))
	}
	want, _, _, _, err := renderXrayConfig(doc3, 10086, "")
	if err != nil {
		t.Fatalf("render doc3: %v", err)
	}
	if string(after) != string(want) {
		t.Fatalf("xray.json after hot apply is not the fresh render of the new config")
	}
	if ap.appliedVersion() != 3 {
		t.Fatalf("applied version = %d, want 3", ap.appliedVersion())
	}
	// Both VLESS inbounds got the same delta: remove rotated u2,
	// add u3 + rotated u2.
	if len(fake.removes) != 2 || len(fake.adds) != 2 {
		t.Fatalf("alter calls: removes=%d adds=%d, want 2 and 2 (one per inbound)", len(fake.removes), len(fake.adds))
	}
	for _, call := range fake.removes {
		if len(call.emails) != 1 || call.emails[0] != "u-merged-ms-1@node" {
			t.Fatalf("remove call %s: emails=%v, want [u-merged-ms-1@node]", call.tag, call.emails)
		}
	}
	for _, call := range fake.adds {
		set := emailSet(call.users)
		if !set["u-sub-su-3@node"] || !set["u-merged-ms-1@node"] || len(set) != 2 {
			t.Fatalf("add call %s: users=%v, want u3 + rotated u2", call.tag, call.users)
		}
		for _, u := range call.users {
			if u.Email == "u-merged-ms-1@node" && u.UUID != "99999999-8888-7777-6666-555555555555" {
				t.Fatalf("rotated user carries old uuid: %v", u)
			}
		}
		if call.tag == "reality-443" {
			for _, u := range call.users {
				if u.Flow != "xtls-rprx-vision" {
					t.Fatalf("reality add user flow = %q, want xtls-rprx-vision", u.Flow)
				}
			}
		}
		if call.tag == "xhttp-443" {
			for _, u := range call.users {
				if u.Flow != "" {
					t.Fatalf("xhttp add user flow = %q, want empty", u.Flow)
				}
			}
		}
	}
}

// TestApplyIdenticalStartsStoppedXray: the 0.1.1/0.1.2 startup bug —
// apply of a config identical to disk must start a stopped Xray
// instead of returning early.
func TestApplyIdenticalStartsStoppedXray(t *testing.T) {
	bin := fakeBinary(t, "sleep 300")
	dir := t.TempDir()
	cfg := &Config{
		XrayPath: bin, XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10085, ControlAddr: "127.0.0.1:0",
	}
	sup := newSupervisor(bin, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	defer sup.Stop()

	doc := testRealityDoc()
	data, _, _, _, err := renderXrayConfig(doc, 10085, "")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := os.WriteFile(cfg.XrayConfigPath, data, 0o600); err != nil {
		t.Fatalf("write disk config: %v", err)
	}
	if sup.IsRunning() {
		t.Fatalf("supervisor should start stopped")
	}
	if err := ap.apply(doc); err != nil {
		t.Fatalf("apply identical: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	if ap.appliedVersion() != doc.ConfigVersion {
		t.Fatalf("applied version = %d, want %d", ap.appliedVersion(), doc.ConfigVersion)
	}
}

// TestApplyAlterFailureFallsBack: when AlterInbound fails, apply must
// fall back to the full rewrite+restart so the end state is correct.
func TestApplyAlterFailureFallsBack(t *testing.T) {
	xrayBin := realXrayBin(t)
	dir := t.TempDir()
	cfg := &Config{
		XrayPath: xrayBin, XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10087, ControlAddr: "127.0.0.1:0",
	}
	sup := newSupervisor(xrayBin, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	ap.alter = &fakeAlter{err: errors.New("api unreachable")}
	defer sup.Stop()

	doc := testRealXrayDoc(10087, 24445, 28445)
	if err := ap.apply(doc); err != nil {
		t.Fatalf("apply #1: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	pid1 := sup.Status().PID

	doc2 := testRealXrayDoc(10087, 24445, 28445)
	doc2.ConfigVersion = 3
	doc2.Users = append(doc2.Users, configUser{
		UserID: "subuser:su-3", Kind: "subuser", ID: "su-3", Name: "u3",
		Email: "u-sub-su-3@node", VLESSUUID: "33333333-4444-5555-6666-777777777777",
	})
	if err := ap.apply(doc2); err != nil {
		t.Fatalf("apply #2 (alter fails): %v", err)
	}
	if pid := sup.Status().PID; pid == pid1 {
		t.Fatalf("fallback did not restart xray (pid still %d)", pid1)
	}
	data, err := os.ReadFile(cfg.XrayConfigPath)
	if err != nil {
		t.Fatalf("read xray.json: %v", err)
	}
	if !strings.Contains(string(data), "33333333-4444-5555-6666-777777777777") {
		t.Fatalf("fallback did not write the new user into xray.json")
	}
	if ap.appliedVersion() != 3 {
		t.Fatalf("applied version = %d, want 3", ap.appliedVersion())
	}
}

// TestPull304RestartsStaleDiskResyncsUsers: after an agent restart
// the disk xray.json predates hot-applied user changes (hot applies
// never rewrite it). A 304 must start Xray and then force one full
// re-sync, so removed users cannot reconnect after a restart.
func TestPull304RestartsStaleDiskResyncsUsers(t *testing.T) {
	// Panel: v4 (users B-rotated + C); 304 when the etag matches.
	panelDoc := testRealityDoc()
	panelDoc.ConfigVersion = 4
	panelDoc.ETag = `"v4"`
	panelDoc.Users[1].VLESSUUID = "99999999-8888-7777-6666-555555555555"
	panelDoc.Users = append(panelDoc.Users, configUser{
		UserID: "subuser:su-3", Kind: "subuser", ID: "su-3", Name: "u3",
		Email: "u-sub-su-3@node", VLESSUUID: "33333333-4444-5555-6666-777777777777",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("If-None-Match") == `"v4"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(panelDoc)
	}))
	defer srv.Close()

	// Disk: the v2 render (users A + B-old), as left by the last
	// full apply before the hot applies.
	diskDoc := testRealityDoc()
	diskData, _, _, _, err := renderXrayConfig(diskDoc, 10085, "")
	if err != nil {
		t.Fatalf("render disk doc: %v", err)
	}
	bin := fakeBinary(t, "sleep 300")
	dir := t.TempDir()
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	cfg.PanelURL = srv.URL
	cfg.XrayPath = bin
	cfg.XrayConfigPath = filepath.Join(dir, "xray.json")
	cfg.APIPort = 10085
	if err := os.WriteFile(cfg.XrayConfigPath, diskData, 0o600); err != nil {
		t.Fatalf("write disk config: %v", err)
	}
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	stateDir := filepath.Join(dir, "state")
	if err := saveState(stateDir, &State{ConfigVersion: 4, ETag: `"v4"`, LastPull: "2026-11-23T00:00:00Z"}); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	sup := newSupervisor(bin, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	fake := &fakeAlter{}
	ap.alter = fake
	defer sup.Stop()

	action, err := pullOnceWithApplier(client, cfg, stateDir, ap)
	if err != nil || action != actionContinue {
		t.Fatalf("pullOnce 304+resync: action=%v err=%v", action, err)
	}
	waitFor(t, 5*time.Second, "xray to start on 304", sup.IsRunning)
	if ap.appliedVersion() != 4 {
		t.Fatalf("applied version = %d, want 4", ap.appliedVersion())
	}
	// The re-sync must hot-apply the user drift (rotate B, add C),
	// not restart Xray: one remove call and one add call per
	// inbound. Slice 4: the hot apply also writes the rendered
	// config to disk, so the disk file now carries the v4 users
	// instead of the stale v2 set (that write is what stops the
	// 0.1.3 stale-disk class of bug from recurring).
	if len(fake.removes) != 2 || len(fake.adds) != 2 {
		t.Fatalf("alter calls: removes=%d adds=%d, want 2 and 2", len(fake.removes), len(fake.adds))
	}
	for _, call := range fake.removes {
		if len(call.emails) != 1 || call.emails[0] != "u-merged-ms-1@node" {
			t.Fatalf("remove call %s: emails=%v, want [u-merged-ms-1@node] (rotation)", call.tag, call.emails)
		}
	}
	for _, call := range fake.adds {
		set := emailSet(call.users)
		if !set["u-merged-ms-1@node"] || !set["u-sub-su-3@node"] || len(set) != 2 {
			t.Fatalf("add call %s: users=%v, want rotated B + C", call.tag, call.users)
		}
		for _, u := range call.users {
			if u.Email == "u-merged-ms-1@node" && u.UUID != "99999999-8888-7777-6666-555555555555" {
				t.Fatalf("rotated user carries old uuid: %v", u)
			}
		}
	}
	after, err := os.ReadFile(cfg.XrayConfigPath)
	if err != nil {
		t.Fatalf("read xray.json: %v", err)
	}
	if string(after) == string(diskData) {
		t.Fatalf("re-sync hot apply left xray.json at the stale v2 set; disk must follow the hot apply")
	}
	if !strings.Contains(string(after), "33333333-4444-5555-6666-777777777777") ||
		!strings.Contains(string(after), "99999999-8888-7777-6666-555555555555") {
		t.Fatalf("xray.json after re-sync lacks the v4 users:\n%s", string(after))
	}
}
func TestPull304EnsuresXray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v3"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodeConfig{OK: true, NodeID: 1, ConfigVersion: 3, ETag: `"v3"`})
	}))
	defer srv.Close()

	// The fake core answers `run -test` with exit 0 (config
	// validation) and sleeps otherwise: the 304 re-sync applies an
	// empty config through the full path, which validates it.
	bin := fakeBinary(t, "if [ \"$2\" = \"-test\" ]; then exit 0; fi\nsleep 300")
	dir := t.TempDir()
	certPEM, keyPEM := genSelfSignedCert(t, "node-1")
	cfg := writeTestCertFiles(t, dir, certPEM, keyPEM)
	cfg.PanelURL = srv.URL
	cfg.XrayPath = bin
	cfg.XrayConfigPath = filepath.Join(dir, "xray.json")
	cfg.APIPort = 10085
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	stateDir := filepath.Join(dir, "state")
	if err := saveState(stateDir, &State{ConfigVersion: 3, ETag: `"v3"`, LastPull: "2026-11-23T00:00:00Z"}); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	sup := newSupervisor(bin, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	defer sup.Stop()

	action, err := pullOnceWithApplier(client, cfg, stateDir, ap)
	if err != nil || action != actionContinue {
		t.Fatalf("pullOnce 304: action=%v err=%v", action, err)
	}
	waitFor(t, 5*time.Second, "xray to start on 304", sup.IsRunning)
}
