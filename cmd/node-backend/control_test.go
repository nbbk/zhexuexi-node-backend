package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// testControl builds a control server on an ephemeral loopback port
// with a running fake supervisor.
func testControl(t *testing.T) (*controlServer, string, *supervisor, *int) {
	t.Helper()
	bin := fakeBinary(t, "sleep 300")
	sup := newSupervisor(bin, filepath.Join(t.TempDir(), "xray.json"))
	if err := sup.Start(); err != nil {
		t.Fatalf("supervisor Start: %v", err)
	}
	t.Cleanup(sup.Stop)
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	reloads := 0
	cs, err := newControlServer("127.0.0.1:0", sup, func() error {
		reloads++
		return nil
	}, func() int { return 7 })
	if err != nil {
		t.Fatalf("newControlServer: %v", err)
	}
	addr, err := cs.Start()
	if err != nil {
		t.Fatalf("control Start: %v", err)
	}
	t.Cleanup(cs.Stop)
	return cs, addr, sup, &reloads
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("GET %s: bad JSON %q: %v", url, body, err)
	}
	return resp.StatusCode, m
}

func postEmpty(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("POST %s: bad JSON %q: %v", url, body, err)
	}
	return resp.StatusCode, m
}

// TestControlHealth: /health reports version, applied config version
// and the supervisor state.
func TestControlHealth(t *testing.T) {
	_, addr, sup, _ := testControl(t)
	code, m := getJSON(t, "http://"+addr+"/health")
	if code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", code)
	}
	if m["ok"] != true || m["version"] != Version {
		t.Fatalf("health body wrong: %v", m)
	}
	if m["config_version"] != float64(7) {
		t.Fatalf("config_version = %v, want 7", m["config_version"])
	}
	if m["xray_running"] != true || m["xray_pid"] != float64(sup.Status().PID) {
		t.Fatalf("xray state wrong: %v", m)
	}
}

// TestControlReload: POST /reload calls the reload func once.
func TestControlReload(t *testing.T) {
	_, addr, _, reloads := testControl(t)
	code, m := postEmpty(t, "http://"+addr+"/reload")
	if code != http.StatusOK || m["ok"] != true {
		t.Fatalf("reload status = %d body %v, want 200 ok", code, m)
	}
	if *reloads != 1 {
		t.Fatalf("reloads = %d, want 1", *reloads)
	}
}

// TestControlReloadError: a failing reload surfaces as 500.
func TestControlReloadError(t *testing.T) {
	bin := fakeBinary(t, "sleep 300")
	sup := newSupervisor(bin, filepath.Join(t.TempDir(), "xray.json"))
	if err := sup.Start(); err != nil {
		t.Fatalf("supervisor Start: %v", err)
	}
	t.Cleanup(sup.Stop)
	cs, err := newControlServer("127.0.0.1:0", sup, func() error {
		return errors.New("panel unreachable")
	}, func() int { return 0 })
	if err != nil {
		t.Fatalf("newControlServer: %v", err)
	}
	addr, err := cs.Start()
	if err != nil {
		t.Fatalf("control Start: %v", err)
	}
	t.Cleanup(cs.Stop)
	code, m := postEmpty(t, "http://"+addr+"/reload")
	if code != http.StatusInternalServerError {
		t.Fatalf("reload status = %d, want 500", code)
	}
	if m["error"] != "panel unreachable" {
		t.Fatalf("reload error body wrong: %v", m)
	}
}

// TestControlRestartCore: POST /restart-core bounces Xray (new pid).
func TestControlRestartCore(t *testing.T) {
	_, addr, sup, _ := testControl(t)
	pid1 := sup.Status().PID
	code, m := postEmpty(t, "http://"+addr+"/restart-core")
	if code != http.StatusOK || m["ok"] != true {
		t.Fatalf("restart-core status = %d body %v, want 200 ok", code, m)
	}
	if pid := sup.Status().PID; pid == pid1 {
		t.Fatalf("restart-core kept pid %d", pid)
	}
}

// TestControlRestartCoreStartsStopped: POST /restart-core with Xray
// down must start it (0.1.2 returned "xray is not running").
func TestControlRestartCoreStartsStopped(t *testing.T) {
	bin := fakeBinary(t, "sleep 300")
	sup := newSupervisor(bin, filepath.Join(t.TempDir(), "xray.json"))
	t.Cleanup(sup.Stop)
	cs, err := newControlServer("127.0.0.1:0", sup, func() error { return nil }, func() int { return 0 })
	if err != nil {
		t.Fatalf("newControlServer: %v", err)
	}
	addr, err := cs.Start()
	if err != nil {
		t.Fatalf("control Start: %v", err)
	}
	t.Cleanup(cs.Stop)
	if sup.IsRunning() {
		t.Fatalf("supervisor should start stopped")
	}
	code, m := postEmpty(t, "http://"+addr+"/restart-core")
	if code != http.StatusOK || m["ok"] != true {
		t.Fatalf("restart-core status = %d body %v, want 200 ok", code, m)
	}
	waitFor(t, 5*time.Second, "xray to start via restart-core", sup.IsRunning)
}

// TestControlReloadStartsStopped: POST /reload with Xray down must
// leave it running after the reload.
func TestControlReloadStartsStopped(t *testing.T) {
	bin := fakeBinary(t, "sleep 300")
	sup := newSupervisor(bin, filepath.Join(t.TempDir(), "xray.json"))
	t.Cleanup(sup.Stop)
	cs, err := newControlServer("127.0.0.1:0", sup, func() error { return nil }, func() int { return 0 })
	if err != nil {
		t.Fatalf("newControlServer: %v", err)
	}
	addr, err := cs.Start()
	if err != nil {
		t.Fatalf("control Start: %v", err)
	}
	t.Cleanup(cs.Stop)
	code, m := postEmpty(t, "http://"+addr+"/reload")
	if code != http.StatusOK || m["ok"] != true {
		t.Fatalf("reload status = %d body %v, want 200 ok", code, m)
	}
	waitFor(t, 5*time.Second, "xray to start via reload", sup.IsRunning)
}

// TestControlMethodNotAllowed: GET on a POST endpoint is 405.
func TestControlMethodNotAllowed(t *testing.T) {
	_, addr, _, _ := testControl(t)
	code, _ := getJSON(t, "http://"+addr+"/reload")
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /reload status = %d, want 405", code)
	}
}

// TestControlRejectsNonLoopback: the control API must never bind a
// non-loopback address.
func TestControlRejectsNonLoopback(t *testing.T) {
	sup := newSupervisor("sleep", "xray.json")
	for _, addr := range []string{"0.0.0.0:18081", "192.0.2.1:18081", "example.com:18081"} {
		if _, err := newControlServer(addr, sup, nil, nil); err == nil {
			t.Fatalf("newControlServer(%q) accepted a non-loopback address", addr)
		}
	}
	if _, err := newControlServer("127.0.0.1:0", sup, nil, nil); err != nil {
		t.Fatalf("newControlServer(127.0.0.1:0) rejected: %v", err)
	}
}
