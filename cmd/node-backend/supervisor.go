package main

import (
	"fmt"
	"log"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// supervisor launches the Xray child process, watches it, and restarts
// it when it dies (build plan §6.2). Crash-loop guard: if the process
// exits within quickExitWindow more than maxQuickExits times in a row,
// the supervisor backs off for backoffDelay and logs the last error
// instead of spinning.
//
// The supervisor never exits on its own: only Stop ends the watch loop.
// All methods are safe for concurrent use.
type supervisor struct {
	xrayPath   string
	configPath string

	// Crash-loop tuning; production defaults in newSupervisor, tests
	// override them with small values.
	quickExitWindow time.Duration
	maxQuickExits   int
	backoffDelay    time.Duration

	mu       sync.Mutex
	cmd      *exec.Cmd
	running  bool
	stopping bool
	// watching reports whether a watch loop is alive. Start() must
	// not spawn a second watch loop while one is alive (e.g. while
	// it is backing off after quick exits): the live loop owns
	// restarts, and a second loop would start a second Xray. Start()
	// after Stop() is not supported: the supervisor is single-use
	// once stopped (runAgent never restarts one).
	watching    bool
	startedAt   time.Time
	pid         int
	restarts    int
	quickExits  int
	lastErr     string
	watchDone   chan struct{} // closed by watch() when the loop exits
	restartDone chan struct{} // closed when a Restart() bounce completes
}

// newSupervisor builds a supervisor with production tuning:
// exit within 10s counts as a quick exit; 3 quick exits in a row
// trigger a 60s backoff.
func newSupervisor(xrayPath, configPath string) *supervisor {
	return &supervisor{
		xrayPath:        xrayPath,
		configPath:      configPath,
		quickExitWindow: 10 * time.Second,
		maxQuickExits:   3,
		backoffDelay:    60 * time.Second,
	}
}

// Start launches Xray once and starts the watch loop. A second call is
// a no-op (use Restart to bounce a running process), as is a call
// while a watch loop is already alive: the live loop owns restarts,
// including after a crash and during backoff.
func (s *supervisor) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.watching {
		// A live watch loop restarts the child itself; if it was
		// stopped, un-stop it so the loop brings the child back.
		s.stopping = false
		return nil
	}
	s.stopping = false
	if err := s.startLocked(); err != nil {
		return err
	}
	s.watching = true
	s.watchDone = make(chan struct{})
	go s.watch()
	return nil
}

// startLocked launches the child; caller holds s.mu. It records the
// start time and pid and resets the quick-exit counter on a clean start.
// The child runs in its own process group so a stop/restart kills the
// whole tree (a shell wrapper's children included), never leaving an
// orphaned grandchild behind holding the log pipe.
func (s *supervisor) startLocked() error {
	cmd := exec.Command(s.xrayPath, "run", "-c", s.configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = log.Writer()
	cmd.Stderr = log.Writer()
	if err := cmd.Start(); err != nil {
		s.lastErr = err.Error()
		return fmt.Errorf("start xray %s: %w", s.xrayPath, err)
	}
	s.cmd = cmd
	s.pid = cmd.Process.Pid
	s.startedAt = time.Now()
	s.running = true
	return nil
}

// watch waits for the child to exit and restarts it unless Stop was
// called. It runs until the supervisor is stopped.
func (s *supervisor) watch() {
	defer close(s.watchDone)
	defer func() {
		s.mu.Lock()
		s.watching = false
		s.mu.Unlock()
	}()
	for {
		s.mu.Lock()
		cmd := s.cmd
		s.mu.Unlock()
		if cmd == nil {
			return
		}
		err := cmd.Wait()
		s.mu.Lock()
		uptime := time.Since(s.startedAt)
		s.running = false
		s.cmd = nil
		if s.stopping {
			s.mu.Unlock()
			return
		}
		if err != nil {
			s.lastErr = err.Error()
		} else {
			s.lastErr = "xray exited (code 0)"
		}
		log.Printf("xray exited after %s: %v; restarting", uptime.Round(time.Second), err)
		if uptime < s.quickExitWindow {
			s.quickExits++
		} else {
			s.quickExits = 0
		}
		if s.quickExits > s.maxQuickExits {
			log.Printf("xray crashed %d times within %s; backing off %s",
				s.quickExits, s.quickExitWindow, s.backoffDelay)
			s.quickExits = 0
			s.mu.Unlock()
			time.Sleep(s.backoffDelay)
			s.mu.Lock()
			if s.stopping {
				s.mu.Unlock()
				return
			}
		}
		if err := s.startLocked(); err != nil {
			log.Printf("xray restart failed: %v; retrying in %s", err, s.backoffDelay)
			s.mu.Unlock()
			time.Sleep(s.backoffDelay)
			s.mu.Lock()
			if s.stopping {
				s.mu.Unlock()
				return
			}
			continue
		}
		s.restarts++
		done := s.restartDone
		s.restartDone = nil // each bounce closes its own channel once
		s.mu.Unlock()
		if done != nil {
			close(done)
		}
	}
}

// signalGroup sends sig to the child's process group (negative pid);
// it falls back to the single process when the group is gone.
func signalGroup(pid int, sig syscall.Signal) {
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(-pid, sig); err != nil {
		_ = syscall.Kill(pid, sig)
	}
}

// Restart bounces the running Xray (config change path): the child is
// killed and the watch loop brings it back. It returns an error when
// nothing is running.
func (s *supervisor) Restart() error {
	s.mu.Lock()
	if !s.running || s.cmd == nil || s.cmd.Process == nil {
		s.mu.Unlock()
		return fmt.Errorf("xray is not running")
	}
	s.restartDone = make(chan struct{})
	done := s.restartDone
	pid := s.pid
	s.mu.Unlock()
	signalGroup(pid, syscall.SIGTERM)
	select {
	case <-done:
		return nil
	case <-time.After(10 * time.Second):
		return fmt.Errorf("xray did not come back within 10s after restart")
	}
}

// Stop ends the watch loop and kills the child (SIGTERM, then SIGKILL
// after 5s). It is safe to call on a stopped supervisor. Only the watch
// loop calls cmd.Wait, so Stop waits on watchDone instead.
func (s *supervisor) Stop() {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return
	}
	s.stopping = true
	var p *exec.Cmd
	var done chan struct{}
	pid := s.pid
	if s.cmd != nil {
		p = s.cmd
	}
	done = s.watchDone
	s.mu.Unlock()
	if p == nil || p.Process == nil {
		return
	}
	signalGroup(pid, syscall.SIGTERM)
	if done != nil {
		select {
		case <-done:
			return
		case <-time.After(5 * time.Second):
		}
	}
	signalGroup(pid, syscall.SIGKILL)
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

// Status is a snapshot for /health and logs.
type supervisorStatus struct {
	Running   bool
	PID       int
	UptimeSec int64
	Restarts  int
	LastErr   string
}

// Status returns the current supervisor snapshot.
func (s *supervisor) Status() supervisorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := supervisorStatus{
		Running:  s.running,
		PID:      s.pid,
		Restarts: s.restarts,
		LastErr:  s.lastErr,
	}
	if s.running {
		st.UptimeSec = int64(time.Since(s.startedAt).Seconds())
	}
	return st
}

// IsRunning reports whether the child is up right now.
func (s *supervisor) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
