package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
)

// XrayVersion is the pinned Xray-core version (build plan §2, §15.2):
// the install script downloads exactly this release, and the rendered
// config pins minClientVer to it.
const XrayVersion = "26.11.9"

// xrayMinClientVer is written explicitly into every REALITY inbound
// (build plan §12 slice 2): clients older than the pinned core are
// refused. It tracks XrayVersion; bump both together.
const xrayMinClientVer = "26.11.9"

// defaultXrayPath is where the install script puts the Xray binary.
const defaultXrayPath = "/usr/local/bin/xray"

// defaultAPIPort is the Xray gRPC API port (dokodemo-door), loopback only.
// The panel's inbound API (10085) is a different port on a different
// machine; the agent's API port is local to the node.
const defaultAPIPort = 10085

// xrayInbound is one enabled inbound rendered into the Xray config.
// Only VLESS over REALITY / XHTTP / TLS is rendered in slice 2; other
// protocols are skipped (sing-box cores are later slices) and logged.
//
// Listen addresses follow the variable principle (2026-11-23): the
// public inbound listen comes from the panel config (in.Listen, empty
// means 0.0.0.0); only the api inbound is pinned to 127.0.0.1, and
// that is a security invariant, not a deployment value — the gRPC API
// must never listen on a public address.
type xrayInbound struct {
	Tag            string `json:"tag"`
	Port           int    `json:"port"`
	Listen         string `json:"listen"`
	Protocol       string `json:"protocol"`
	Settings       any    `json:"settings"`
	StreamSettings any    `json:"streamSettings,omitempty"`
}

// xrayConfig is the rendered Xray config document (JSON). Keys follow
// Xray's infra/conf format.
type xrayConfig struct {
	Log       map[string]any `json:"log"`
	API       map[string]any `json:"api"`
	Stats     map[string]any `json:"stats"`
	Policy    map[string]any `json:"policy"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []any          `json:"outbounds"`
	Routing   map[string]any `json:"routing"`
}

// renderXrayConfig renders the panel config doc into an Xray config
// document. It returns the JSON bytes and their SHA-256 hex (used to
// decide whether the running Xray needs a restart).
//
// Rules (build plan §6, §7):
//   - api dokodemo-door on 127.0.0.1:APIPort, always present;
//   - VLESS + REALITY (+Vision flow) -> reality inbound on the panel port;
//   - VLESS + XHTTP + REALITY -> xhttp inbound (server only, never in
//     subscriptions); clients get no flow (XHTTP + Vision is invalid);
//   - VLESS + TLS + Vision -> tls inbound; certs come in slice 7, so a
//     TLS inbound without a cert file errors out instead of rendering;
//   - any other protocol (hysteria2, tuic, trojan, vmess, ss, socks,
//     ...) is skipped and the skip is returned in skippedTags;
//   - two enabled Xray inbounds on the same TCP port is an error
//     (the panel already guards this; the agent is the last line).
func renderXrayConfig(doc *nodeConfig, apiPort int) (configJSON []byte, sha string, skippedTags []string, err error) {
	if apiPort <= 0 || apiPort > 65535 {
		return nil, "", nil, fmt.Errorf("invalid api port %d", apiPort)
	}
	users := vlessClients(doc.Users)
	inbounds := []xrayInbound{
		{
			Tag:      "api",
			Port:     apiPort,
			Listen:   "127.0.0.1",
			Protocol: "dokodemo-door",
			Settings: map[string]any{"address": "127.0.0.1"},
		},
	}
	usedTCPPorts := map[int]string{}
	for _, in := range doc.Inbounds {
		if !in.Enabled {
			continue
		}
		if in.Protocol != "vless" {
			skippedTags = append(skippedTags, in.InboundTag)
			continue
		}
		xb, skip, err := renderVLESSInbound(in, users)
		if err != nil {
			return nil, "", nil, fmt.Errorf("inbound %s: %w", in.InboundTag, err)
		}
		if skip {
			skippedTags = append(skippedTags, in.InboundTag)
			continue
		}
		if prev, ok := usedTCPPorts[xb.Port]; ok {
			return nil, "", nil, fmt.Errorf("TCP port %d is used by both %s and %s", xb.Port, prev, xb.Tag)
		}
		usedTCPPorts[xb.Port] = xb.Tag
		inbounds = append(inbounds, *xb)
	}
	sort.Strings(skippedTags)

	cfg := xrayConfig{
		Log: map[string]any{"loglevel": "warning"},
		API: map[string]any{
			"tag":      "api",
			"services": []string{"HandlerService", "LoggerService", "StatsService"},
		},
		Stats: map[string]any{},
		Policy: map[string]any{
			"levels": map[string]any{
				"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true},
			},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		Inbounds: inbounds,
		Outbounds: []any{
			map[string]any{"protocol": "freedom", "tag": "direct"},
			map[string]any{"protocol": "blackhole", "tag": "block"},
		},
		Routing: map[string]any{
			"rules": []any{
				map[string]any{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
			},
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, "", nil, fmt.Errorf("encode xray config: %w", err)
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), skippedTags, nil
}

// vlessClients turns panel users into VLESS client entries. Disabled
// users and users without a UUID are left out. The email is the Xray
// user>>> stats key (u-sub-<id>@node / u-merged-<id>@node, same as the
// old D10 agent interface); flow is set per inbound, not here.
func vlessClients(users []configUser) []map[string]any {
	clients := []map[string]any{}
	for _, u := range users {
		if u.Disabled || strings.TrimSpace(u.VLESSUUID) == "" {
			continue
		}
		clients = append(clients, map[string]any{
			"id":    u.VLESSUUID,
			"email": u.Email,
		})
	}
	return clients
}

// inboundListen resolves a panel inbound's listen address: the
// configured value, or 0.0.0.0 when empty. An invalid value is an
// error (fail closed: never render a config Xray cannot bind).
func inboundListen(in configInbound) (string, error) {
	l := strings.TrimSpace(in.Listen)
	if l == "" {
		return "0.0.0.0", nil
	}
	if net.ParseIP(l) == nil {
		return "", fmt.Errorf("invalid listen address %q", l)
	}
	return l, nil
}

// renderVLESSInbound renders one VLESS inbound. skip=true means the
// combination is not an Xray inbound in this slice (TLS without a cert
// file is an error instead, because the user explicitly asked for it).
func renderVLESSInbound(in configInbound, users []map[string]any) (*xrayInbound, bool, error) {
	if in.Port <= 0 || in.Port > 65535 {
		return nil, false, fmt.Errorf("invalid port %d", in.Port)
	}
	listen, err := inboundListen(in)
	if err != nil {
		return nil, false, err
	}
	clients := make([]map[string]any, 0, len(users))
	switch strings.ToLower(in.Transport) {
	case "reality":
		if in.Security != "reality" {
			return nil, true, nil
		}
		for _, c := range users {
			cc := map[string]any{"id": c["id"], "email": c["email"]}
			if f := strings.TrimSpace(in.Flow); f != "" {
				cc["flow"] = f
			}
			clients = append(clients, cc)
		}
		reality, err := realitySettings(in)
		if err != nil {
			return nil, false, err
		}
		return &xrayInbound{
			Tag:      in.InboundTag,
			Port:     in.Port,
			Listen:   listen,
			Protocol: "vless",
			Settings: map[string]any{"clients": clients, "decryption": "none"},
			StreamSettings: map[string]any{
				"network":         "tcp",
				"security":        "reality",
				"realitySettings": reality,
			},
		}, false, nil
	case "xhttp":
		if in.Security != "reality" {
			return nil, true, nil
		}
		// XHTTP clients must not carry a flow (XHTTP + Vision is invalid
		// in Xray); the panel's xhttp inbound has no flow set.
		for _, c := range users {
			clients = append(clients, map[string]any{"id": c["id"], "email": c["email"]})
		}
		reality, err := realitySettings(in)
		if err != nil {
			return nil, false, err
		}
		return &xrayInbound{
			Tag:      in.InboundTag,
			Port:     in.Port,
			Listen:   listen,
			Protocol: "vless",
			Settings: map[string]any{"clients": clients, "decryption": "none"},
			StreamSettings: map[string]any{
				"network":         "xhttp",
				"security":        "reality",
				"realitySettings": reality,
				"xhttpSettings": map[string]any{
					"path": "/",
					"mode": "auto",
				},
			},
		}, false, nil
	case "tcp":
		switch in.Security {
		case "tls":
			// TLS certs are issued and shipped by the panel in slice 7;
			// until then a TLS inbound cannot be rendered.
			return nil, false, fmt.Errorf("TLS inbound needs a certificate file (slice 7); no certs shipped yet")
		case "none":
			// Plain TCP VLESS is deliberately not served: no camouflage.
			return nil, true, nil
		default:
			return nil, true, nil
		}
	default:
		return nil, true, nil
	}
}

// realitySettings builds the REALITY server block. minClientVer is
// written explicitly and pinned to the core version (XrayVersion).
func realitySettings(in configInbound) (map[string]any, error) {
	if strings.TrimSpace(in.RealityPrivateKey) == "" {
		return nil, fmt.Errorf("missing reality private key")
	}
	if strings.TrimSpace(in.RealityShortID) == "" {
		return nil, fmt.Errorf("missing reality short id")
	}
	serverNames := strings.TrimSpace(in.RealityServerName)
	if serverNames == "" {
		serverNames = strings.TrimSpace(in.SNI)
	}
	if serverNames == "" {
		return nil, fmt.Errorf("missing reality server name (SNI)")
	}
	names := []string{}
	for _, n := range strings.Split(serverNames, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	dest := strings.TrimSpace(in.RealityDest)
	if dest == "" {
		dest = "www.example.com:443"
	}
	return map[string]any{
		"show":         false,
		"dest":         dest,
		"xver":         0,
		"serverNames":  names,
		"privateKey":   in.RealityPrivateKey,
		"minClientVer": xrayMinClientVer,
		"shortIds":     []string{in.RealityShortID},
	}, nil
}

// validateXrayConfig runs `xray run -test -c <path>` and returns an
// error carrying the binary's output tail when the config is invalid.
// The config is never applied without passing this check.
func validateXrayConfig(xrayPath, configPath string) error {
	cmd := exec.Command(xrayPath, "run", "-test", "-c", configPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		tail := strings.TrimSpace(out.String())
		if len(tail) > 800 {
			tail = tail[len(tail)-800:]
		}
		return fmt.Errorf("xray config test failed: %v: %s", err, tail)
	}
	return nil
}
