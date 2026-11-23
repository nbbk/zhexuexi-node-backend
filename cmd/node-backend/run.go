package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// PollInterval is the config pull interval (slice 1: pull only).
const PollInterval = 60 * time.Second

// State is the persisted pull state at <state-dir>/state.json.
type State struct {
	ConfigVersion int    `json:"config_version"`
	ETag          string `json:"etag"`
	LastPull      string `json:"last_pull"`
}

// configApplier applies a pulled panel config to Xray: render, test,
// write, then start or restart the supervised child (slice 2). A render
// or validation failure leaves the running Xray untouched and is
// returned so the caller can log it; the next config change retries.
type configApplier struct {
	cfg *Config
	sup *supervisor

	mu      sync.Mutex
	version int
}

// newConfigApplier builds an applier for cfg.
func newConfigApplier(cfg *Config, sup *supervisor) *configApplier {
	return &configApplier{cfg: cfg, sup: sup}
}

// appliedVersion is the panel config version currently applied to Xray
// (0 before the first successful apply).
func (a *configApplier) appliedVersion() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.version
}

// apply renders nc and, when the rendered config differs from the file
// on disk, validates it with `xray run -test`, writes it, and starts or
// restarts Xray. A nil nc (304) is a no-op.
func (a *configApplier) apply(nc *nodeConfig) error {
	if nc == nil {
		return nil
	}
	data, sha, skipped, err := renderXrayConfig(nc, a.cfg.APIPort)
	if err != nil {
		return fmt.Errorf("render xray config: %w", err)
	}
	for _, tag := range skipped {
		log.Printf("inbound %s skipped: not an Xray inbound in this slice", tag)
	}
	if existing, err := os.ReadFile(a.cfg.XrayConfigPath); err == nil {
		sum := sha256.Sum256(existing)
		if hex.EncodeToString(sum[:]) == sha {
			a.mu.Lock()
			a.version = nc.ConfigVersion
			a.mu.Unlock()
			return nil
		}
	}
	// Write to a temp file in the same directory, validate, then rename
	// into place so Xray never sees a half-written config. The temp
	// file keeps a .json suffix: Xray picks the config format from the
	// file extension, and a bare .tmp fails with "failed to get format".
	tmpFile, err := os.CreateTemp(filepath.Dir(a.cfg.XrayConfigPath), ".xray-*.json")
	if err != nil {
		return fmt.Errorf("create xray config temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write xray config temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close xray config temp file: %w", err)
	}
	if err := validateXrayConfig(a.cfg.XrayPath, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, a.cfg.XrayConfigPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("install xray config: %w", err)
	}
	log.Printf("xray config written: version=%d sha=%s inbounds=%d users=%d",
		nc.ConfigVersion, sha[:12], len(nc.Inbounds), len(nc.Users))
	if !a.sup.IsRunning() {
		if err := a.sup.Start(); err != nil {
			return fmt.Errorf("start xray: %w", err)
		}
		log.Printf("xray started (pid %d)", a.sup.Status().PID)
	} else if err := a.sup.Restart(); err != nil {
		return fmt.Errorf("restart xray: %w", err)
	}
	a.mu.Lock()
	a.version = nc.ConfigVersion
	a.mu.Unlock()
	return nil
}

// runAction is what pullOnce tells the run loop to do next.
type runAction int

const (
	// actionContinue: keep polling.
	actionContinue runAction = iota
	// actionDeleted: the panel deleted this node; stop cleanly (exit 0,
	// systemd must not restart the agent).
	actionDeleted
)

// loadState reads <state-dir>/state.json. A missing file is not an error:
// it just means no successful pull has happened yet.
func loadState(stateDir string) (*State, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, "state.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return &State{}, nil
		}
		return nil, fmt.Errorf("read state %s: %w", filepath.Join(stateDir, "state.json"), err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	return &st, nil
}

// saveState writes <state-dir>/state.json (mode 0600, atomic rename).
func saveState(stateDir string, st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	data = append(data, '\n')
	return writeFileAtomic(filepath.Join(stateDir, "state.json"), data, 0o600)
}

// runAgent parses flags, loads the config, starts the Xray supervisor
// and the loopback control API, pulls once immediately and then every
// PollInterval. Pull errors are logged and retried next cycle; the
// agent never exits on a transient failure. A deleted node stops Xray
// and exits 0. SIGINT/SIGTERM stop Xray and exit 0.
func runAgent(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configDir := fs.String("config-dir", DefaultConfigDir, "config directory")
	stateDir := fs.String("state-dir", DefaultStateDir, "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configDir)
	if err != nil {
		return err
	}
	client, err := newHTTPClient(cfg, nil)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory %s: %w", *stateDir, err)
	}

	sup := newSupervisor(cfg.XrayPath, cfg.XrayConfigPath)
	applier := newConfigApplier(cfg, sup)
	pull := func() error {
		_, err := pullOnceWithApplier(client, cfg, *stateDir, applier)
		return err
	}
	ctrl, err := newControlServer(cfg.ControlAddr, sup, pull, applier.appliedVersion)
	if err != nil {
		return err
	}
	if _, err := ctrl.Start(); err != nil {
		return err
	}
	defer ctrl.Stop()

	// SIGINT/SIGTERM: stop Xray cleanly, then exit 0 (systemd stop).
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("node-backend %s stopping: node_id=%d", Version, cfg.NodeID)
		sup.Stop()
		os.Exit(0)
	}()

	log.Printf("node-backend %s starting: node_id=%d panel=%s xray=%s control=%s",
		Version, cfg.NodeID, cfg.PanelURL, cfg.XrayPath, cfg.ControlAddr)
	for {
		action, err := pullOnceWithApplier(client, cfg, *stateDir, applier)
		if err != nil {
			log.Printf("config pull failed: %v; retrying in %s", err, PollInterval)
		}
		if action == actionDeleted {
			log.Printf("node %d was deleted on the panel; stopping Xray and exiting (exit 0)", cfg.NodeID)
			sup.Stop()
			os.Exit(0)
		}
		time.Sleep(PollInterval)
	}
}

// pullOnce performs a single pull cycle: read the stored etag, pull,
// persist the new state on a 200, and report the action to take.
// applier may be nil (no Xray apply, used by tests).
func pullOnce(client *http.Client, cfg *Config, stateDir string) (runAction, error) {
	return pullOnceWithApplier(client, cfg, stateDir, nil)
}

// pullOnceWithApplier is pullOnce with an Xray applier. On a 200 the
// config is applied first (render/test/write/start-or-restart Xray);
// an apply error is returned after the state is saved, so the run loop
// logs it once and retries on the next config change.
func pullOnceWithApplier(client *http.Client, cfg *Config, stateDir string, applier *configApplier) (runAction, error) {
	st, err := loadState(stateDir)
	if err != nil {
		return actionContinue, err
	}
	status, nc, err := pullConfig(client, cfg.PanelURL, st.ETag)
	if err != nil {
		return actionContinue, err
	}
	switch status {
	case pullNotModified:
		log.Printf("config unchanged (etag %s)", st.ETag)
		return actionContinue, nil
	case pullDeleted:
		return actionDeleted, nil
	case pullOK:
		newState := &State{
			ConfigVersion: nc.ConfigVersion,
			ETag:          nc.ETag,
			LastPull:      time.Now().UTC().Format(time.RFC3339),
		}
		if err := saveState(stateDir, newState); err != nil {
			return actionContinue, fmt.Errorf("save state: %w", err)
		}
		log.Printf("config pulled: version=%d etag=%s inbounds=%d users=%d certs=%d",
			nc.ConfigVersion, nc.ETag, len(nc.Inbounds), len(nc.Users), len(nc.Certs))
		if applier != nil {
			if err := applier.apply(nc); err != nil {
				return actionContinue, fmt.Errorf("apply config: %w", err)
			}
		}
		return actionContinue, nil
	default:
		return actionContinue, fmt.Errorf("unexpected pull status %q", status)
	}
}
