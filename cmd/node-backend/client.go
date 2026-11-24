package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// configInbound is one inbound from GET /api/v1/node/config. Field
// names match the panel's NodeInbound JSON (panel/node_backend.go).
type configInbound struct {
	NodeID             int64  `json:"node_id"`
	InboundID          int64  `json:"inbound_id"`
	InboundTag         string `json:"inbound_tag"`
	Protocol           string `json:"protocol"`
	Transport          string `json:"transport"`
	Security           string `json:"security"`
	Port               int    `json:"port"`
	Listen             string `json:"listen"`
	SNI                string `json:"sni"`
	Domain             string `json:"domain"`
	RealityPrivateKey  string `json:"reality_private_key"`
	RealityPublicKey   string `json:"reality_public_key"`
	RealityShortID     string `json:"reality_short_id"`
	RealityDest        string `json:"reality_dest"`
	RealityServerName  string `json:"reality_server_names"`
	RealityFingerprint string `json:"reality_fingerprint"`
	CertRef            int64  `json:"cert_ref"`
	Flow               string `json:"flow"`
	SSMethod           string `json:"ss_method"`
	SSPassword         string `json:"ss_password"`
	SocksUsername      string `json:"socks_username"`
	SocksPassword      string `json:"socks_password"`
	Enabled            bool   `json:"enabled"`
}

// configUser is one user from GET /api/v1/node/config. VLESSUUID is
// this user's UUID on this node; Email is the Xray user>>> stats key.
// Inbounds (slice 4) is the per-inbound assignment: the tags of the
// inbounds this user may use. Missing or empty means all inbounds.
type configUser struct {
	UserID    string   `json:"user_id"`
	Kind      string   `json:"kind"`
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Email     string   `json:"email"`
	VLESSUUID string   `json:"vless_uuid"`
	Disabled  bool     `json:"disabled"`
	Inbounds  []string `json:"inbounds,omitempty"`
}

// nodeConfig is the body of GET /api/v1/node/config. Certs stay raw
// JSON in slice 2: certificate issue and delivery is slice 7 work.
type nodeConfig struct {
	OK            bool              `json:"ok"`
	NodeID        int               `json:"node_id"`
	ConfigVersion int               `json:"config_version"`
	ETag          string            `json:"etag"`
	Deleted       bool              `json:"deleted"`
	Inbounds      []configInbound   `json:"inbounds"`
	Users         []configUser      `json:"users"`
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

// userKey is the panel's kind:id identity for a user, used as the
// user_key in traffic reports. It comes from the pulled config's
// user_id field ("subuser:su-1" / "merged:ms-1"); when the field is
// absent it is derived from the Xray email, whose format is the one
// the panel actually emits (u-sub-<id>@node / u-merged-<id>@node,
// not the build plan's user-<id>@panel example).
func userKey(u configUser) string {
	if strings.TrimSpace(u.UserID) != "" {
		return u.UserID
	}
	return userKeyForEmail(u.Email)
}

// userKeyForEmail derives the kind:id key from an Xray email. An
// unrecognised email is returned as-is rather than dropped: the
// traffic row must survive, and the panel can still match it.
func userKeyForEmail(email string) string {
	if rest, ok := strings.CutPrefix(email, "u-sub-"); ok {
		if id, ok := strings.CutSuffix(rest, "@node"); ok {
			return "subuser:" + id
		}
	}
	if rest, ok := strings.CutPrefix(email, "u-merged-"); ok {
		if id, ok := strings.CutSuffix(rest, "@node"); ok {
			return "merged:" + id
		}
	}
	return email
}

// postTraffic posts one traffic window to POST /api/v1/node/traffic
// with the mTLS client. Any transport error or non-2xx status is an
// error (the caller spools the window for replay).
func postTraffic(client *http.Client, panelURL string, rep trafficReport) error {
	data, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("encode traffic report: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, panelURL+"/api/v1/node/traffic", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build traffic request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Backend-Version", Version)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s/api/v1/node/traffic: %w", panelURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("panel returned status %d for traffic report", resp.StatusCode)
	}
	return nil
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
