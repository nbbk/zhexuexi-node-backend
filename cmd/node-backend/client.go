package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// nodeConfig is the body of GET /api/v1/node/config. Inbounds, users and
// certs are kept as raw JSON in slice 1: the agent only needs version,
// etag and the deleted flag here; applying the contents is slice 2 work.
type nodeConfig struct {
	OK            bool              `json:"ok"`
	NodeID        int               `json:"node_id"`
	ConfigVersion int               `json:"config_version"`
	ETag          string            `json:"etag"`
	Deleted       bool              `json:"deleted"`
	Inbounds      []json.RawMessage `json:"inbounds"`
	Users         []json.RawMessage `json:"users"`
	Certs         []json.RawMessage `json:"certs"`
	Error         string            `json:"error"`
}

// pullStatus describes the outcome of one config pull.
type pullStatus string

const (
	// pullOK: 200 with a live config.
	pullOK pullStatus = "ok"
	// pullNotModified: 304, config unchanged.
	pullNotModified pullStatus = "not-modified"
	// pullDeleted: 200 with deleted=true, the node was removed on the panel.
	pullDeleted pullStatus = "deleted"
)

// newHTTPClient builds the mTLS client used for config pulls. It presents
// the client certificate obtained at join time. rootCAs is nil in
// production (system roots); tests pass their own CA pool.
func newHTTPClient(cfg *Config, rootCAs *x509.CertPool) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate %s / %s: %w", cfg.CertFile, cfg.KeyFile, err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		RootCAs:      rootCAs,
	}
	if cfg.Insecure {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // explicit config from join --insecure
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Second,
	}, nil
}

// pullConfig fetches GET /api/v1/node/config once. etag is the value from
// the previous successful pull ("" on the first pull) and is sent as
// If-None-Match. A 304 returns (pullNotModified, nil, nil). Any transport
// error, unexpected status or malformed body returns a non-nil error.
func pullConfig(client *http.Client, panelURL, etag string) (pullStatus, *nodeConfig, error) {
	req, err := http.NewRequest(http.MethodGet, panelURL+"/api/v1/node/config", nil)
	if err != nil {
		return "", nil, fmt.Errorf("build config request: %w", err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	req.Header.Set("X-Node-Backend-Version", Version)

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("GET %s/api/v1/node/config: %w", panelURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return pullNotModified, nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", nil, fmt.Errorf("read config response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var errBody nodeConfig
		if json.Unmarshal(body, &errBody) == nil && errBody.Error != "" {
			return "", nil, fmt.Errorf("panel returned status %d: %s", resp.StatusCode, errBody.Error)
		}
		return "", nil, fmt.Errorf("panel returned status %d", resp.StatusCode)
	}
	var nc nodeConfig
	if err := json.Unmarshal(body, &nc); err != nil {
		return "", nil, fmt.Errorf("parse config response: %w", err)
	}
	if !nc.OK {
		return "", nil, fmt.Errorf("panel reported failure: %s", nc.Error)
	}
	if nc.Deleted {
		return pullDeleted, &nc, nil
	}
	return pullOK, &nc, nil
}
