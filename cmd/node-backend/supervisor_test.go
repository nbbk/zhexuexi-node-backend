package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// fakeBinary writes a small shell script that behaves like a core
// binary for supervision tests: it ignores argv and runs body.
func fakeBinary(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-core")
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	return path
}

// waitFor polls cond until it is true or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestSupervisorRestartOnKill: killing the child must bring it back
// with a new pid within 5 seconds (slice 2 acceptance).
func TestSupervisorRestartOnKill(t *testing.T) {
	bin := fakeBinary(t, "sleep 300")
	sup := newSupervisor(bin, filepath.Join(t.TempDir(), "xray.json"))
	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop()

	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	pid1 := sup.Status().PID
	if pid1 <= 0 {
		t.Fatalf("pid = %d", pid1)
	}
	if err := syscall.Kill(pid1, syscall.SIGKILL); err != nil {
		t.Fatalf("kill pid %d: %v", pid1, err)
	}
	started := time.Now()
	waitFor(t, 5*time.Second, "xray to restart with a new pid", func() bool {
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

// TestSupervisorCrashBackoff: a child that exits immediately must not
// spin: after maxQuickExits quick exits the supervisor backs off and
// the restart count stays bounded.
func TestSupervisorCrashBackoff(t *testing.T) {
	bin := fakeBinary(t, "exit 1")
	sup := newSupervisor(bin, filepath.Join(t.TempDir(), "xray.json"))
	sup.quickExitWindow = 500 * time.Millisecond
	sup.maxQuickExits = 2
	sup.backoffDelay = 2 * time.Second
	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop()

	// Let it crash-loop for a while; the backoff must bound restarts.
	time.Sleep(3 * time.Second)
	restarts := sup.Status().Restarts
	if restarts == 0 {
		t.Fatalf("crashing child was never restarted")
	}
	if restarts > 6 {
		t.Fatalf("restarts = %d in 3s, backoff did not bound the loop", restarts)
	}
	if got := sup.Status().LastErr; got == "" {
		t.Fatalf("last error empty after crashes")
	}
}

// TestSupervisorStop: Stop kills the child and the supervisor reports
// not running; a second Stop is safe. The fake core spawns a
// grandchild (sh -> sleep): the process-group kill must take the
// grandchild down too, or it would linger holding the log pipe.
func TestSupervisorStop(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	// The supervisor runs <bin> run -c <configPath>: $3 is the pid file.
	bin := fakeBinary(t, "sleep 300 & echo $! > \"$3\"; wait")
	sup := newSupervisor(bin, pidFile)
	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	pid := sup.Status().PID
	waitFor(t, 5*time.Second, "grandchild pid file", func() bool {
		_, err := os.Stat(pidFile)
		return err == nil
	})
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read grandchild pid: %v", err)
	}
	var grandchild int
	if _, err := fmt.Sscanf(string(raw), "%d", &grandchild); err != nil || grandchild <= 0 {
		t.Fatalf("grandchild pid = %q: %v", raw, err)
	}
	sup.Stop()
	if sup.IsRunning() {
		t.Fatalf("supervisor still running after Stop")
	}
	// The child must be gone (kill signal 0 errors).
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("child pid %d still alive after Stop", pid)
	}
	// …and so must the grandchild. It may linger as a zombie until
	// init reaps it, so poll briefly instead of a single check.
	waitFor(t, 5*time.Second, "grandchild to die", func() bool {
		return syscall.Kill(grandchild, 0) != nil
	})
	sup.Stop() // second Stop must not panic or hang
}

// TestSupervisorStartTwice: a second Start is a no-op, not a second child.
func TestSupervisorStartTwice(t *testing.T) {
	bin := fakeBinary(t, "sleep 300")
	sup := newSupervisor(bin, filepath.Join(t.TempDir(), "xray.json"))
	if err := sup.Start(); err != nil {
		t.Fatalf("Start #1: %v", err)
	}
	defer sup.Stop()
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	pid1 := sup.Status().PID
	if err := sup.Start(); err != nil {
		t.Fatalf("Start #2: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if pid := sup.Status().PID; pid != pid1 {
		t.Fatalf("second Start replaced the child: %d -> %d", pid1, pid)
	}
}

// TestSupervisorRestart: Restart bounces the child and returns once
// the new child is up.
func TestSupervisorRestart(t *testing.T) {
	bin := fakeBinary(t, "sleep 300")
	sup := newSupervisor(bin, filepath.Join(t.TempDir(), "xray.json"))
	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop()
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	pid1 := sup.Status().PID
	if err := sup.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if pid := sup.Status().PID; pid == pid1 {
		t.Fatalf("Restart kept the same pid %d", pid)
	}
	if err := syscall.Kill(pid1, 0); err == nil {
		t.Fatalf("old child pid %d still alive after Restart", pid1)
	}
}
