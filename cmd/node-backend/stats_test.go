package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestParseStatsquery: the pinned Xray 26.11.9 prints one JSON
// document; a counter with no traffic yet omits `value` (read as 0);
// an empty result is {}.
func TestParseStatsquery(t *testing.T) {
	out := []byte(`{"stat": [
		{"name": "inbound>>>reality-443>>>traffic>>>uplink", "value": 12345},
		{"name": "inbound>>>reality-443>>>traffic>>>downlink"},
		{"name": "user>>>u-sub-su-1@node>>>traffic>>>uplink", "value": 100},
		{"name": "user>>>u-sub-su-1@node>>>traffic>>>downlink", "value": 200},
		{"name": "inbound>>>api>>>traffic>>>uplink", "value": 999}
	]}`)
	sample, err := parseStatsquery(out)
	if err != nil {
		t.Fatalf("parseStatsquery: %v", err)
	}
	if sample["inbound>>>reality-443>>>traffic>>>uplink"] != 12345 {
		t.Fatalf("uplink = %d, want 12345", sample["inbound>>>reality-443>>>traffic>>>uplink"])
	}
	if sample["inbound>>>reality-443>>>traffic>>>downlink"] != 0 {
		t.Fatalf("missing value must read as 0, got %d", sample["inbound>>>reality-443>>>traffic>>>downlink"])
	}
	if sample["user>>>u-sub-su-1@node>>>traffic>>>downlink"] != 200 {
		t.Fatalf("user downlink = %d, want 200", sample["user>>>u-sub-su-1@node>>>traffic>>>downlink"])
	}
	if _, err := parseStatsquery([]byte(`{}`)); err != nil {
		t.Fatalf("empty result must parse: %v", err)
	}
	if _, err := parseStatsquery([]byte(`not json`)); err == nil {
		t.Fatalf("garbage output must fail to parse")
	}
}

// TestStatsAccumulatorDelta: first sample only seeds the baseline;
// later samples give increments; a counter missing from the
// baseline counts from 0; a counter that went down (restart) only
// clears the baseline, never subtracts back; the api inbound is
// skipped (it only carries the agent's own API calls).
func TestStatsAccumulatorDelta(t *testing.T) {
	acc := &statsAccumulator{}
	first := statsSample{
		"user>>>u-sub-su-1@node>>>traffic>>>uplink":   1000,
		"user>>>u-sub-su-1@node>>>traffic>>>downlink": 2000,
		"inbound>>>reality-443>>>traffic>>>uplink":    5000,
		"inbound>>>reality-443>>>traffic>>>downlink":  6000,
		"inbound>>>api>>>traffic>>>uplink":            999,
		"inbound>>>api>>>traffic>>>downlink":          888,
		"some>>>unknown>>>counter":                    42,
	}
	if d := acc.delta(first); len(d.users) != 0 || len(d.inbounds) != 0 {
		t.Fatalf("first sample must only seed the baseline, got %+v", d)
	}
	second := statsSample{
		"user>>>u-sub-su-1@node>>>traffic>>>uplink":   1500,
		"user>>>u-sub-su-1@node>>>traffic>>>downlink": 2000, // no change
		"user>>>u-sub-su-2@node>>>traffic>>>uplink":   700,  // new counter: counts from 0
		"user>>>u-sub-su-2@node>>>traffic>>>downlink": 300,
		"inbound>>>reality-443>>>traffic>>>uplink":    5500,
		"inbound>>>reality-443>>>traffic>>>downlink":  6000,
		"inbound>>>api>>>traffic>>>uplink":            1999,
		"inbound>>>api>>>traffic>>>downlink":          1888,
		"some>>>unknown>>>counter":                    43,
	}
	d := acc.delta(second)
	if got := d.users["u-sub-su-1@node"]; got != [2]int64{500, 0} {
		t.Fatalf("u1 delta = %v, want [500 0]", got)
	}
	if got := d.users["u-sub-su-2@node"]; got != [2]int64{700, 300} {
		t.Fatalf("new counter delta = %v, want [700 300] (baseline 0)", got)
	}
	if got := d.inbounds["reality-443"]; got != [2]int64{500, 0} {
		t.Fatalf("reality delta = %v, want [500 0]", got)
	}
	if _, ok := d.inbounds["api"]; ok {
		t.Fatalf("api inbound must be skipped, got %+v", d.inbounds)
	}
	// Xray restart: counters reset to small values; the delta is 0
	// for this window (baseline cleared, nothing subtracted back).
	third := statsSample{
		"user>>>u-sub-su-1@node>>>traffic>>>uplink":   10,
		"user>>>u-sub-su-1@node>>>traffic>>>downlink": 20,
		"inbound>>>reality-443>>>traffic>>>uplink":    5,
		"inbound>>>reality-443>>>traffic>>>downlink":  6,
	}
	d = acc.delta(third)
	if len(d.users) != 0 || len(d.inbounds) != 0 {
		t.Fatalf("counter reset must give a zero delta, got %+v", d)
	}
	// And the next window counts from the new baseline.
	fourth := statsSample{
		"user>>>u-sub-su-1@node>>>traffic>>>uplink":   110,
		"user>>>u-sub-su-1@node>>>traffic>>>downlink": 120,
		"inbound>>>reality-443>>>traffic>>>uplink":    105,
		"inbound>>>reality-443>>>traffic>>>downlink":  106,
	}
	d = acc.delta(fourth)
	if got := d.users["u-sub-su-1@node"]; got != [2]int64{100, 100} {
		t.Fatalf("post-reset delta = %v, want [100 100]", got)
	}
}

// TestParseCounterNames: user>>> and inbound>>> shapes, and the
// rejects (wrong prefix, wrong segment count, bad direction).
func TestParseCounterNames(t *testing.T) {
	if email, dir, ok := parseUserCounter("user>>>u-sub-su-1@node>>>traffic>>>uplink"); !ok || email != "u-sub-su-1@node" || dir != 0 {
		t.Fatalf("user uplink parse failed: %q %d %v", email, dir, ok)
	}
	if email, dir, ok := parseUserCounter("user>>>u-merged-ms-1@node>>>traffic>>>downlink"); !ok || email != "u-merged-ms-1@node" || dir != 1 {
		t.Fatalf("user downlink parse failed: %q %d %v", email, dir, ok)
	}
	if tag, dir, ok := parseInboundCounter("inbound>>>reality-443>>>traffic>>>downlink"); !ok || tag != "reality-443" || dir != 1 {
		t.Fatalf("inbound parse failed: %q %d %v", tag, dir, ok)
	}
	for _, bad := range []string{
		"user>>>u-sub-su-1@node>>>traffic>>>sideways",
		"user>>>u-sub-su-1@node>>>uplink",
		"inbound>>>reality-443>>>traffic>>>uplink>>>extra",
		"outbound>>>direct>>>traffic>>>uplink",
		"",
	} {
		if _, _, ok := parseUserCounter(bad); ok {
			t.Fatalf("parseUserCounter(%q) should reject", bad)
		}
		if _, _, ok := parseInboundCounter(bad); ok {
			t.Fatalf("parseInboundCounter(%q) should reject", bad)
		}
	}
}

// TestUserKey: the panel kind:id form comes from user_id; without
// it the email is mapped (u-sub- / u-merged- prefixes, @node
// suffix); an unrecognised email passes through unchanged.
func TestUserKey(t *testing.T) {
	cases := []struct {
		u    configUser
		want string
	}{
		{configUser{UserID: "subuser:su-1", Email: "u-sub-su-1@node"}, "subuser:su-1"},
		{configUser{UserID: "merged:ms-1", Email: "u-merged-ms-1@node"}, "merged:ms-1"},
		{configUser{Email: "u-sub-su-9@node"}, "subuser:su-9"},
		{configUser{Email: "u-merged-ms-9@node"}, "merged:ms-9"},
		{configUser{Email: "weird@example.com"}, "weird@example.com"},
		{configUser{Email: ""}, ""},
	}
	for _, c := range cases {
		if got := userKey(c.u); got != c.want {
			t.Fatalf("userKey(%+v) = %q, want %q", c.u, got, c.want)
		}
	}
}

// TestRenderPerInboundAssignment: a user with an inbounds list
// renders only into those inbounds; a user with no list renders
// everywhere (old behaviour); a user assigned only to a non-Xray
// inbound renders nowhere in Xray.
func TestRenderPerInboundAssignment(t *testing.T) {
	doc := testRealityDoc()
	doc.Users[0].Inbounds = []string{"reality-443"} // u1: reality only
	doc.Users[1].Inbounds = []string{"hy2-443"}     // u2: sing-box only, not Xray
	doc.Users = append(doc.Users, configUser{
		UserID: "subuser:su-3", Kind: "subuser", ID: "su-3", Name: "u3",
		Email: "u-sub-su-3@node", VLESSUUID: "33333333-4444-5555-6666-777777777777",
	}) // u3: no list, everywhere
	data, _, _, _, err := renderXrayConfig(doc, 10085, "")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	p := parseXrayJSON(t, data)
	reality := p.inboundByTag(t, "reality-443")
	clients, _ := strMap(t, reality["settings"])["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("reality clients = %d, want 2 (u1 + u3)", len(clients))
	}
	emails := map[string]bool{}
	for _, c := range clients {
		emails[strMap(t, c)["email"].(string)] = true
	}
	if !emails["u-sub-su-1@node"] || !emails["u-sub-su-3@node"] {
		t.Fatalf("reality clients wrong: %v", emails)
	}
	xhttp := p.inboundByTag(t, "xhttp-443")
	xclients, _ := strMap(t, xhttp["settings"])["clients"].([]any)
	if len(xclients) != 1 {
		t.Fatalf("xhttp clients = %d, want 1 (u3 only)", len(xclients))
	}
	if strMap(t, xclients[0])["email"] != "u-sub-su-3@node" {
		t.Fatalf("xhttp client wrong: %v", xclients[0])
	}
	// Assignment also feeds the hot path: the per-inbound sets must
	// split the same way.
	targets, err := vlessTargets(doc, "")
	if err != nil {
		t.Fatalf("vlessTargets: %v", err)
	}
	sets := byInboundSets(effectiveUsers(doc.Users), targets)
	if len(sets["reality-443"]) != 2 || len(sets["xhttp-443"]) != 1 {
		t.Fatalf("byInboundSets = %v, want reality 2 / xhttp 1", sets)
	}
	if _, ok := sets["xhttp-443"]["u-sub-su-1@node"]; ok {
		t.Fatalf("u1 must not be in the xhttp set")
	}
}

// TestApplyPerInboundMove: moving a user from reality-only to
// xhttp-only must remove from reality and add to xhttp (one call
// each), without restarting Xray.
func TestApplyPerInboundMove(t *testing.T) {
	bin := fakeBinary(t, "if [ \"$2\" = \"-test\" ]; then exit 0; fi\nsleep 300")
	dir := t.TempDir()
	cfg := &Config{
		XrayPath: bin, XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10085, ControlAddr: "127.0.0.1:0",
	}
	sup := newSupervisor(bin, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	fake := &fakeAlter{}
	ap.alter = fake
	defer sup.Stop()

	docA := testRealityDoc()
	docA.Users = docA.Users[:1] // only u1
	docA.Users[0].Inbounds = []string{"reality-443"}
	if err := ap.apply(docA); err != nil {
		t.Fatalf("apply A: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	pid1 := sup.Status().PID

	docB := testRealityDoc()
	docB.ConfigVersion = 3
	docB.Users = docB.Users[:1]
	docB.Users[0].Inbounds = []string{"xhttp-443"}
	if err := ap.apply(docB); err != nil {
		t.Fatalf("apply B (move inbound): %v", err)
	}
	if pid := sup.Status().PID; pid != pid1 {
		t.Fatalf("inbound move restarted xray: %d -> %d", pid1, pid)
	}
	if len(fake.removes) != 1 || fake.removes[0].tag != "reality-443" ||
		len(fake.removes[0].emails) != 1 || fake.removes[0].emails[0] != "u-sub-su-1@node" {
		t.Fatalf("removes = %+v, want one remove from reality-443", fake.removes)
	}
	if len(fake.adds) != 1 || fake.adds[0].tag != "xhttp-443" ||
		len(fake.adds[0].users) != 1 || fake.adds[0].users[0].Email != "u-sub-su-1@node" {
		t.Fatalf("adds = %+v, want one add to xhttp-443", fake.adds)
	}
}

// TestApplyStaleDiskDeleteRegression (slice 4 bug, 2026-11-23):
// the disk xray.json is stale (v2: users A+B) while the applied
// memory set is v3 (A+B+C, hot-added, never written to disk — the
// 0.1.3 state). Removing C renders byte-identical to the disk
// file; the old code returned early on that SHA match and the
// removal never reached Xray. The fix decides from memory: the
// removal must still call AlterInbound.
func TestApplyStaleDiskDeleteRegression(t *testing.T) {
	bin := fakeBinary(t, "if [ \"$2\" = \"-test\" ]; then exit 0; fi\nsleep 300")
	dir := t.TempDir()
	cfg := &Config{
		XrayPath: bin, XrayConfigPath: filepath.Join(dir, "xray.json"),
		APIPort: 10085, ControlAddr: "127.0.0.1:0",
	}
	sup := newSupervisor(bin, cfg.XrayConfigPath)
	ap := newConfigApplier(cfg, sup, nil)
	fake := &fakeAlter{}
	ap.alter = fake
	defer sup.Stop()

	// Disk: the v2 render (users A + B), as 0.1.3 left it.
	diskDoc := testRealityDoc()
	diskData, _, _, _, err := renderXrayConfig(diskDoc, 10085, "")
	if err != nil {
		t.Fatalf("render disk doc: %v", err)
	}
	if err := writeFileAtomic(cfg.XrayConfigPath, diskData, 0o600); err != nil {
		t.Fatalf("write disk config: %v", err)
	}
	// Memory: v3 applied set (A + B + C), as if C had been
	// hot-added and the disk never updated.
	v3 := testRealityDoc()
	v3.ConfigVersion = 3
	v3.Users = append(v3.Users, configUser{
		UserID: "subuser:su-3", Kind: "subuser", ID: "su-3", Name: "u3",
		Email: "u-sub-su-3@node", VLESSUUID: "33333333-4444-5555-6666-777777777777",
	})
	v3Data, _, _, _, err := renderXrayConfig(v3, 10085, "")
	if err != nil {
		t.Fatalf("render v3: %v", err)
	}
	structure, err := structureSHA(v3Data)
	if err != nil {
		t.Fatalf("structure sha: %v", err)
	}
	users3 := effectiveUsers(v3.Users)
	targets3, err := vlessTargets(v3, "")
	if err != nil {
		t.Fatalf("vlessTargets: %v", err)
	}
	ap.setApplied(3, users3, byInboundSets(users3, targets3), targets3, structure)
	if err := sup.Start(); err != nil {
		t.Fatalf("start supervisor: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)

	// Panel removes C (v4). The fresh render is byte-identical to
	// the stale disk file — the exact case 0.1.3 skipped.
	v4 := testRealityDoc()
	v4.ConfigVersion = 4
	v4Data, _, _, _, err := renderXrayConfig(v4, 10085, "")
	if err != nil {
		t.Fatalf("render v4: %v", err)
	}
	if string(v4Data) != string(diskData) {
		t.Fatalf("test setup broken: v4 render must equal the stale disk file")
	}
	if err := ap.apply(v4); err != nil {
		t.Fatalf("apply v4 (remove C): %v", err)
	}
	if len(fake.removes) != 2 {
		t.Fatalf("removes = %+v, want one remove per VLESS inbound (C must reach AlterInbound even though render==disk)", fake.removes)
	}
	for _, call := range fake.removes {
		if len(call.emails) != 1 || call.emails[0] != "u-sub-su-3@node" {
			t.Fatalf("remove call %s: emails=%v, want [u-sub-su-3@node]", call.tag, call.emails)
		}
	}
	if len(fake.adds) != 0 {
		t.Fatalf("adds = %+v, want none", fake.adds)
	}
	if ap.appliedVersion() != 4 {
		t.Fatalf("applied version = %d, want 4", ap.appliedVersion())
	}
	// And the disk now agrees with the running state again.
	after, err := os.ReadFile(cfg.XrayConfigPath)
	if err != nil {
		t.Fatalf("read xray.json: %v", err)
	}
	if string(after) != string(v4Data) {
		t.Fatalf("disk after hot remove is not the v4 render")
	}
}
