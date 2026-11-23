package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
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

// runAgent parses flags, loads the config, pulls once immediately and
// then every PollInterval. Pull errors are logged and retried next cycle;
// the agent never exits on a transient failure. A deleted node logs and
// exits 0.
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

	log.Printf("node-backend %s starting: node_id=%d panel=%s", Version, cfg.NodeID, cfg.PanelURL)
	for {
		action, err := pullOnce(client, cfg, *stateDir)
		if err != nil {
			log.Printf("config pull failed: %v; retrying in %s", err, PollInterval)
		}
		if action == actionDeleted {
			log.Printf("node %d was deleted on the panel; stopping (exit 0)", cfg.NodeID)
			os.Exit(0)
		}
		time.Sleep(PollInterval)
	}
}

// pullOnce performs a single pull cycle: read the stored etag, pull,
// persist the new state on a 200, and report the action to take.
func pullOnce(client *http.Client, cfg *Config, stateDir string) (runAction, error) {
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
		return actionContinue, nil
	default:
		return actionContinue, fmt.Errorf("unexpected pull status %q", status)
	}
}
