package main

import (
	"context"
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
//
// Slice 3: a change that only touches users (add/remove/rotate) is
// hot-applied through the Xray API (AlterInbound, see alter.go) with
// no file write and no restart. The applier remembers the applied
// user set and the "structure" of the applied config (the rendered
// config with user lists stripped) so it can tell the two apart. On
// agent restart the applied set is seeded from the xray.json on disk.
type configApplier struct {
	cfg *Config
	sup *supervisor

	mu      sync.Mutex
	version int
	// alter applies user deltas to a running Xray; nil means the
	// default cliAlterClient (tests inject a fake).
	alter alterClient
	// appliedUsers is the user set last applied to Xray, keyed by
	// email; appliedStructure is its stripped-structure SHA.
	appliedUsers     map[string]configUser
	appliedStructure string
	// seeded reports whether appliedUsers/appliedStructure were
	// loaded (from disk or from a previous apply in this process).
	seeded bool
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

// setApplied records a successful apply (full or hot) under the lock.
func (a *configApplier) setApplied(version int, users map[string]configUser, structure string) {
	a.mu.Lock()
	a.version = version
	a.appliedUsers = users
	a.appliedStructure = structure
	a.seeded = true
	a.mu.Unlock()
}

// seedFromDisk loads the applied user set and structure from the
// xray.json on disk (the last full apply, which survives an agent
// restart). A missing or unparseable file is not an error: the next
// apply simply takes the full path.
func (a *configApplier) seedFromDisk() {
	data, err := os.ReadFile(a.cfg.XrayConfigPath)
	if err != nil {
		return
	}
	users, structure, err := usersAndStructureFromRendered(data)
	if err != nil {
		log.Printf("seed applied users from %s: %v; will full-apply on next change", a.cfg.XrayConfigPath, err)
		return
	}
	a.mu.Lock()
	a.appliedUsers = users
	a.appliedStructure = structure
	a.seeded = true
	a.mu.Unlock()
}

// ensureXrayRunning starts Xray when it is not running (the 0.1.1 /
// 0.1.2 startup bug: a SHA-identical config or a 304 returned early
// without ever starting Xray, so an agent or server restart left the
// node down until the panel changed the config). It seeds the applied
// user set from disk first so a later user-only diff has a baseline.
// It reports whether it actually started Xray: the 304 caller uses
// that to decide whether a full re-sync is needed (the on-disk
// config predates hot-applied user changes). When Xray is already
// running this is a no-op returning false.
func (a *configApplier) ensureXrayRunning() (bool, error) {
	a.mu.Lock()
	seeded := a.seeded
	a.mu.Unlock()
	if !seeded {
		a.seedFromDisk()
	}
	if a.sup.IsRunning() {
		return false, nil
	}
	if err := a.sup.Start(); err != nil {
		return false, fmt.Errorf("start xray: %w", err)
	}
	log.Printf("xray started (pid %d)", a.sup.Status().PID)
	return true, nil
}

// resyncAfterRestart forces one full config pull (no If-None-Match)
// and applies it. It runs after a 304 that (re)started Xray from the
// on-disk config: hot applies never rewrite that file, so the disk
// config may predate the last user-only changes, and a 304 alone
// would leave removed users able to reconnect until the panel next
// changes the config. The apply diffs against the disk-seeded user
// set, so a user-only drift is fixed by AlterInbound, not a restart.
func (a *configApplier) resyncAfterRestart(client *http.Client, cfg *Config, stateDir string) (runAction, error) {
	log.Printf("xray restarted from disk config; forcing a full config re-sync")
	status, nc, err := pullConfig(client, cfg.PanelURL, "")
	if err != nil {
		return actionContinue, err
	}
	switch status {
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
		log.Printf("config re-synced: version=%d etag=%s inbounds=%d users=%d certs=%d",
			nc.ConfigVersion, nc.ETag, len(nc.Inbounds), len(nc.Users), len(nc.Certs))
		if err := a.apply(nc); err != nil {
			return actionContinue, fmt.Errorf("apply config: %w", err)
		}
		return actionContinue, nil
	default:
		return actionContinue, fmt.Errorf("unexpected pull status %q", status)
	}
}

// alterClientFor returns the AlterInbound client, defaulting to the
// xray binary's own `api` subcommand.
func (a *configApplier) alterClientFor() alterClient {
	if a.alter != nil {
		return a.alter
	}
	return &cliAlterClient{xrayPath: a.cfg.XrayPath}
}

// apply renders nc and applies it to Xray. A nil nc (304) is a no-op.
//   - rendered config identical to disk (users included): ensure Xray
//     is running, record the version, return (no restart);
//   - only users changed: hot-apply the delta via AlterInbound, no
//     file write, no restart; on AlterInbound failure fall back to
//     the full path so the end state is still correct;
//   - anything else changed: validate, write, start or restart Xray.
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
	newUsers := effectiveUsers(nc.Users)
	structure, err := structureSHA(data)
	if err != nil {
		return fmt.Errorf("structure sha: %w", err)
	}
	a.mu.Lock()
	seeded := a.seeded
	a.mu.Unlock()
	if !seeded {
		a.seedFromDisk()
	}
	if existing, err := os.ReadFile(a.cfg.XrayConfigPath); err == nil {
		sum := sha256.Sum256(existing)
		if hex.EncodeToString(sum[:]) == sha {
			if _, err := a.ensureXrayRunning(); err != nil {
				return err
			}
			a.setApplied(nc.ConfigVersion, newUsers, structure)
			return nil
		}
	}
	a.mu.Lock()
	appliedUsers := a.appliedUsers
	appliedStructure := a.appliedStructure
	seeded = a.seeded
	a.mu.Unlock()
	if seeded && appliedStructure == structure {
		if usersEqual(appliedUsers, newUsers) {
			if _, err := a.ensureXrayRunning(); err != nil {
				return err
			}
			a.setApplied(nc.ConfigVersion, newUsers, structure)
			return nil
		}
		targets, err := vlessTargets(nc)
		if err != nil {
			return fmt.Errorf("vless targets: %w", err)
		}
		serverAddr := fmt.Sprintf("127.0.0.1:%d", a.cfg.APIPort)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := applyUserDiff(ctx, a.alterClientFor(), serverAddr, targets, appliedUsers, newUsers); err != nil {
			log.Printf("AlterInbound failed (%v); falling back to full rewrite+restart", err)
		} else {
			a.setApplied(nc.ConfigVersion, newUsers, structure)
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
	a.setApplied(nc.ConfigVersion, newUsers, structure)
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
		// 304 means the panel config is unchanged, not that Xray is
		// up: an agent or server restart lands exactly here, so
		// ensure Xray is running (and seed the applied user set
		// from disk for later user-only diffs). When the ensure
		// actually (re)started Xray, the on-disk config it started
		// from may predate hot-applied user changes, so force one
		// full re-sync to close that gap.
		if applier != nil {
			started, err := applier.ensureXrayRunning()
			if err != nil {
				return actionContinue, fmt.Errorf("ensure xray running: %w", err)
			}
			if started {
				return applier.resyncAfterRestart(client, cfg, stateDir)
			}
		}
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
