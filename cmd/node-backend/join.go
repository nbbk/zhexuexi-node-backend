package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// joinRequest is the body of POST /api/v1/node-backend/join.
type joinRequest struct {
	NodeID int    `json:"node_id"`
	Token  string `json:"token"`
}

// joinResponse is the body of a successful join reply. On failure the
// panel returns {"ok": false, "error": "..."} with a 4xx status.
type joinResponse struct {
	OK            bool   `json:"ok"`
	NodeID        int    `json:"node_id"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
	Error         string `json:"error"`
}

// runJoin parses flags and performs the join flow.
func runJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	panel := fs.String("panel", "", "panel base URL, e.g. https://example.com:11111")
	token := fs.String("token", "", "join token, join_<32 hex chars>")
	nodeID := fs.Int("node-id", 0, "node id as registered on the panel")
	insecure := fs.Bool("insecure", false, "skip panel TLS certificate verification (dev only)")
	configDir := fs.String("config-dir", DefaultConfigDir, "config directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *panel == "" {
		return errors.New("--panel is required")
	}
	if *token == "" {
		return errors.New("--token is required")
	}
	if *nodeID <= 0 {
		return errors.New("--node-id is required and must be positive")
	}
	return doJoin(*panel, *token, *nodeID, *insecure, *configDir)
}

// doJoin exchanges the join token for a client certificate, then writes
// the certificate, key and config. Nothing is written until the panel
// has accepted the token, and a failure while writing the config removes
// the certificate/key again, so join never leaves a half-written setup.
func doJoin(panelURL, token string, nodeID int, insecure bool, configDir string) error {
	panelURL = strings.TrimRight(panelURL, "/")

	body, err := json.Marshal(joinRequest{NodeID: nodeID, Token: token})
	if err != nil {
		return fmt.Errorf("encode join request: %w", err)
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, //nolint:gosec // explicit --insecure flag
	}}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	resp, err := client.Post(panelURL+"/api/v1/node-backend/join", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST %s/api/v1/node-backend/join: %w", panelURL, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read join response: %w", err)
	}

	var jr joinResponse
	if err := json.Unmarshal(respBody, &jr); err != nil {
		return fmt.Errorf("parse join response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || !jr.OK {
		msg := jr.Error
		if msg == "" {
			msg = fmt.Sprintf("panel returned status %d", resp.StatusCode)
		}
		return fmt.Errorf("join rejected: %s", msg)
	}
	if jr.ClientCertPEM == "" || jr.ClientKeyPEM == "" {
		return errors.New("join succeeded but panel returned an empty certificate or key")
	}
	// Sanity-check the pair before writing anything: the cert and key
	// must parse and match, otherwise the agent could never use them.
	if _, err := tls.X509KeyPair([]byte(jr.ClientCertPEM), []byte(jr.ClientKeyPEM)); err != nil {
		return fmt.Errorf("panel returned an unusable certificate/key pair: %w", err)
	}

	certFile := certFilePath(configDir)
	keyFile := keyFilePath(configDir)
	if err := writeFileAtomic(certFile, []byte(jr.ClientCertPEM), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(keyFile, []byte(jr.ClientKeyPEM), 0o600); err != nil {
		os.Remove(certFile)
		return err
	}
	cfg := &Config{
		PanelURL: panelURL,
		NodeID:   nodeID,
		CertFile: certFile,
		KeyFile:  keyFile,
		Insecure: insecure,
	}
	if err := saveConfig(configDir, cfg); err != nil {
		os.Remove(certFile)
		os.Remove(keyFile)
		return err
	}
	return nil
}
