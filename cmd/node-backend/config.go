package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultConfigDir is where config.json and certs/ live in production.
const DefaultConfigDir = "/etc/node-backend"

// DefaultStateDir is where state.json lives in production.
const DefaultStateDir = "/var/lib/node-backend"

// Config is the agent configuration written by `join` and read by `run`.
// It is stored at <config-dir>/config.json with mode 0600.
type Config struct {
	PanelURL string `json:"panel_url"`
	NodeID   int    `json:"node_id"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	Insecure bool   `json:"insecure"`
}

// certFilePath returns the client certificate path for a config dir.
func certFilePath(configDir string) string {
	return filepath.Join(configDir, "certs", "node.crt")
}

// keyFilePath returns the client private key path for a config dir.
func keyFilePath(configDir string) string {
	return filepath.Join(configDir, "certs", "node.key")
}

// loadConfig reads <config-dir>/config.json.
func loadConfig(configDir string) (*Config, error) {
	data, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", filepath.Join(configDir, "config.json"), err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.PanelURL == "" || cfg.NodeID == 0 || cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("config incomplete: panel_url, node_id, cert_file and key_file are all required")
	}
	return &cfg, nil
}

// writeFileAtomic writes data to path with mode perm via a temp file in
// the same directory followed by rename, so a crash never leaves a
// half-written file behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	return nil
}

// saveConfig writes cfg to <config-dir>/config.json with mode 0600.
func saveConfig(configDir string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	return writeFileAtomic(filepath.Join(configDir, "config.json"), data, 0o600)
}
