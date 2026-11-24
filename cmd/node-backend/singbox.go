package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/nbbk/zhexuexi-node-backend/cmd/node-backend/v2rayapi"
)

// SingboxVersion is the pinned sing-box version (build plan §2, §15.2):
// the install script downloads exactly this release.
const SingboxVersion = "1.14.4"

// singboxV2RayTimeout bounds one V2Ray API stats query.
const singboxV2RayTimeout = 5 * time.Second

// singboxInbound is one enabled inbound rendered into the sing-box
// config. Only HY2 / TUIC / AnyTLS are rendered in slice 5; other
// protocols are Xray's job and are skipped (logged by the caller).
//
// One credential per user: the user's VLESS UUID (build plan §12
// slice 5 detail). HY2 password = UUID; TUIC uuid + password = UUID;
// AnyTLS password = UUID. All three carry name = the user's Xray
// email (ASCII, unique per user): the inbound writes it into
// metadata.User, so the V2Ray API stats service counts per-user
// traffic under it (build plan §9.4). Slice 10 subscription
// rendering uses the same mapping, so a UUID works on every protocol.
type singboxInbound struct {
	Type    string         `json:"type"`
	Tag     string         `json:"tag"`
	Listen  string         `json:"listen"`
	Port    int            `json:"listen_port"`
	Users   []any          `json:"users"`
	TLS     map[string]any `json:"tls,omitempty"`
	CongCtl string         `json:"congestion_control,omitempty"`
}

// singboxConfig is the rendered sing-box config document (JSON).
type singboxConfig struct {
	Log          map[string]any   `json:"log"`
	Experimental map[string]any   `json:"experimental"`
	Inbounds     []singboxInbound `json:"inbounds"`
	Outbounds    []any            `json:"outbounds"`
	Route        map[string]any   `json:"route"`
}

// certFiles resolves a panel CertRef to the certificate files the
// agent expects (build plan §12 slice 5 interim contract, slice 7
// delivers them): <certsDir>/<ref>.crt and <certsDir>/<ref>.key.
// Both must exist; a missing file is reported, not guessed.
func certFiles(certsDir string, ref int64) (crt, key string, err error) {
	if ref <= 0 {
		return "", "", fmt.Errorf("no certificate reference (cert_ref %d)", ref)
	}
	crt = fmt.Sprintf("%s/%d.crt", strings.TrimSuffix(certsDir, "/"), ref)
	key = fmt.Sprintf("%s/%d.key", strings.TrimSuffix(certsDir, "/"), ref)
	if _, err := os.Stat(crt); err != nil {
		return "", "", fmt.Errorf("certificate file %s missing: %w", crt, err)
	}
	if _, err := os.Stat(key); err != nil {
		return "", "", fmt.Errorf("certificate key %s missing: %w", key, err)
	}
	return crt, key, nil
}

// singboxDomain is the TLS domain for a sing-box inbound: the SNI
// (the panel requires a real domain for HY2/TUIC/AnyTLS), falling
// back to the Domain field. Empty means the panel sent an inbound
// the agent cannot serve.
func singboxDomain(in configInbound) string {
	if d := strings.TrimSpace(in.SNI); d != "" {
		return d
	}
	return strings.TrimSpace(in.Domain)
}

// singboxUserName is the metering identity of a user on a sing-box
// inbound: the user's Xray email (ASCII, unique per user), falling
// back to the user ID when the email is empty. All three sing-box
// inbounds write this name into metadata.User, so the V2Ray API
// stats service counts per-user traffic under it (build plan §9.4).
func singboxUserName(u configUser) string {
	if name := strings.TrimSpace(u.Email); name != "" {
		return name
	}
	return strings.TrimSpace(u.UserID)
}

// singboxUsers is the per-inbound user list for a sing-box inbound:
// enabled users with a UUID, filtered by the slice 4 per-inbound
// assignment (empty Inbounds = all inbounds). Each entry carries
// the metering name and the credential UUID.
type singboxUser struct {
	Name string
	UUID string
}

func singboxUsers(users []configUser, tag string) []singboxUser {
	out := []singboxUser{}
	for _, u := range users {
		if u.Disabled || strings.TrimSpace(u.VLESSUUID) == "" {
			continue
		}
		if tag != "" && len(u.Inbounds) > 0 && !slicesContains(u.Inbounds, tag) {
			continue
		}
		out = append(out, singboxUser{Name: singboxUserName(u), UUID: u.VLESSUUID})
	}
	return out
}

// singboxTLS builds the TLS block shared by all three sing-box
// inbounds. alpn is set for HY2/TUIC (h3); AnyTLS leaves it empty.
func singboxTLS(domain, crt, key string, alpn []string) map[string]any {
	tls := map[string]any{
		"enabled":          true,
		"server_name":      domain,
		"certificate_path": crt,
		"key_path":         key,
	}
	if len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	return tls
}

// renderSingboxConfig renders the panel config doc into a sing-box
// config document. It returns the JSON bytes and their SHA-256 hex
// (used to decide whether the running sing-box needs a restart),
// the tags skipped because they are not sing-box inbounds, and the
// tags skipped because their certificate is not on disk yet
// (slice 7 delivers certificates; a missing cert skips the inbound
// and logs, it never renders a TLS inbound without one).
//
// Rules (build plan §6, §12 slice 5):
//   - hysteria2 / tuic: QUIC transport, UDP port, TLS with cert;
//   - anytls: TCP + TLS, TLS with cert;
//   - any other protocol (vless, trojan, ss, socks, ...) is skipped;
//   - two enabled sing-box inbounds on the same UDP port is an error
//     (the panel already guards UDP 443; the agent is the last line),
//     same for the same TCP port.
func renderSingboxConfig(doc *nodeConfig, certsDir string) (configJSON []byte, sha string, skippedTags []string, needsCertTags []string, err error) {
	inbounds := []singboxInbound{}
	usedUDPPorts := map[int]string{}
	usedTCPPorts := map[int]string{}
	for _, in := range doc.Inbounds {
		if !in.Enabled {
			continue
		}
		proto := strings.ToLower(in.Protocol)
		if proto != "hysteria2" && proto != "tuic" && proto != "anytls" {
			skippedTags = append(skippedTags, in.InboundTag)
			continue
		}
		if in.Port <= 0 || in.Port > 65535 {
			return nil, "", nil, nil, fmt.Errorf("inbound %s: invalid port %d", in.InboundTag, in.Port)
		}
		listen, err := inboundListen(in)
		if err != nil {
			return nil, "", nil, nil, fmt.Errorf("inbound %s: %w", in.InboundTag, err)
		}
		domain := singboxDomain(in)
		if domain == "" {
			return nil, "", nil, nil, fmt.Errorf("inbound %s: missing domain (SNI) for %s", in.InboundTag, proto)
		}
		crt, key, err := certFiles(certsDir, in.CertRef)
		if err != nil {
			needsCertTags = append(needsCertTags, in.InboundTag)
			continue
		}
		uuids := singboxUsers(doc.Users, in.InboundTag)
		users := make([]any, 0, len(uuids))
		switch proto {
		case "hysteria2":
			if strings.ToLower(in.Transport) != "quic" {
				return nil, "", nil, nil, fmt.Errorf("inbound %s: hysteria2 needs QUIC transport", in.InboundTag)
			}
			if prev, ok := usedUDPPorts[in.Port]; ok {
				return nil, "", nil, nil, fmt.Errorf("UDP port %d is used by both %s and %s", in.Port, prev, in.InboundTag)
			}
			usedUDPPorts[in.Port] = in.InboundTag
			for _, u := range uuids {
				users = append(users, map[string]any{"name": u.Name, "password": u.UUID})
			}
			inbounds = append(inbounds, singboxInbound{
				Type: "hysteria2", Tag: in.InboundTag, Listen: listen, Port: in.Port,
				Users: users, TLS: singboxTLS(domain, crt, key, []string{"h3"}),
			})
		case "tuic":
			if strings.ToLower(in.Transport) != "quic" {
				return nil, "", nil, nil, fmt.Errorf("inbound %s: tuic needs QUIC transport", in.InboundTag)
			}
			if prev, ok := usedUDPPorts[in.Port]; ok {
				return nil, "", nil, nil, fmt.Errorf("UDP port %d is used by both %s and %s", in.Port, prev, in.InboundTag)
			}
			usedUDPPorts[in.Port] = in.InboundTag
			for _, u := range uuids {
				users = append(users, map[string]any{"name": u.Name, "uuid": u.UUID, "password": u.UUID})
			}
			inbounds = append(inbounds, singboxInbound{
				Type: "tuic", Tag: in.InboundTag, Listen: listen, Port: in.Port,
				Users: users, TLS: singboxTLS(domain, crt, key, []string{"h3"}),
				CongCtl: "bbr",
			})
		case "anytls":
			if strings.ToLower(in.Transport) != "tcp" || strings.ToLower(in.Security) != "tls" {
				return nil, "", nil, nil, fmt.Errorf("inbound %s: anytls needs TCP+TLS", in.InboundTag)
			}
			if prev, ok := usedTCPPorts[in.Port]; ok {
				return nil, "", nil, nil, fmt.Errorf("TCP port %d is used by both %s and %s", in.Port, prev, in.InboundTag)
			}
			usedTCPPorts[in.Port] = in.InboundTag
			for _, u := range uuids {
				users = append(users, map[string]any{"name": u.Name, "password": u.UUID})
			}
			inbounds = append(inbounds, singboxInbound{
				Type: "anytls", Tag: in.InboundTag, Listen: listen, Port: in.Port,
				Users: users, TLS: singboxTLS(domain, crt, key, nil),
			})
		}
	}
	sort.Strings(skippedTags)
	sort.Strings(needsCertTags)

	// V2Ray API stats (build plan §9.4): the stats service counts
	// per inbound tag and per user name, so the rendered config
	// lists every rendered inbound tag and every rendered user
	// name. The agent queries it on loopback (querySingboxStats).
	statsTags := make([]string, 0, len(inbounds))
	statsUsers := map[string]bool{}
	for _, in := range inbounds {
		statsTags = append(statsTags, in.Tag)
		for _, u := range singboxUsers(doc.Users, in.Tag) {
			statsUsers[u.Name] = true
		}
	}
	sort.Strings(statsTags)
	statsUserList := make([]string, 0, len(statsUsers))
	for name := range statsUsers {
		statsUserList = append(statsUserList, name)
	}
	sort.Strings(statsUserList)

	cfg := singboxConfig{
		Log: map[string]any{"level": "warn"},
		Experimental: map[string]any{
			"v2ray_api": map[string]any{
				"listen": defaultSingboxV2RayAddr,
				"stats": map[string]any{
					"enabled":  true,
					"inbounds": statsTags,
					"users":    statsUserList,
				},
			},
		},
		Inbounds: inbounds,
		Outbounds: []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
		Route: map[string]any{"final": "direct"},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, "", nil, nil, fmt.Errorf("encode sing-box config: %w", err)
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), skippedTags, needsCertTags, nil
}

// validateSingboxConfig runs `sing-box check -c <path>` and returns an
// error carrying the binary's output tail when the config is invalid.
// The config is never applied without passing this check. (check
// passing does not guarantee run works — the local end-to-end test
// runs the real binary; see build plan §13.2.)
func validateSingboxConfig(singboxPath, configPath string) error {
	cmd := exec.Command(singboxPath, "check", "-c", configPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		tail := strings.TrimSpace(out.String())
		if len(tail) > 800 {
			tail = tail[len(tail)-800:]
		}
		return fmt.Errorf("sing-box config check failed: %v: %s", err, tail)
	}
	return nil
}

// querySingboxStats reads every counter from the sing-box V2Ray
// API stats service on loopback (QueryStats with no patterns
// returns all counters). Counter names are the V2Ray shapes:
//   - inbound>>><tag>>>>traffic>>>uplink / downlink (per inbound)
//   - user>>><name>>>>traffic>>>uplink / downlink (per user name)
//
// The service only exists in the agent's custom sing-box build
// (with_v2ray_api tag, build plan §9.4); the official binary
// answers "unknown service" instead. The gRPC service name is
// v2ray.core.app.stats.command.StatsService, not Xray's
// xray.app.stats.command.StatsService, so `xray api statsquery`
// cannot be used — this native client is the query path.
func querySingboxStats(addr string) (map[string]int64, error) {
	if addr == "" {
		addr = defaultSingboxV2RayAddr
	}
	ctx, cancel := context.WithTimeout(context.Background(), singboxV2RayTimeout)
	defer cancel()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial sing-box v2ray api %s: %w", addr, err)
	}
	defer conn.Close()
	client := v2rayapi.NewStatsServiceClient(conn)
	resp, err := client.QueryStats(ctx, &v2rayapi.QueryStatsRequest{})
	if err != nil {
		return nil, fmt.Errorf("query sing-box stats %s: %w", addr, err)
	}
	out := make(map[string]int64, len(resp.Stat))
	for _, s := range resp.Stat {
		out[s.Name] = s.Value
	}
	return out, nil
}

// singboxDelta is one window of sing-box traffic: per-inbound and
// per-user deltas, each [uplink, downlink] bytes.
type singboxDelta struct {
	inbounds map[string][2]int64
	users    map[string][2]int64
}

// singboxCounterAccumulator turns cumulative V2Ray API counters
// into per-window deltas, one accumulator per counter name. The
// first sample seeds the baseline (no delta). A decrease means
// sing-box restarted and its counters reset: the whole sample is
// the delta. Counters that never appear are simply absent.
type singboxCounterAccumulator struct {
	last map[string]int64
	seen bool
}

func (a *singboxCounterAccumulator) delta(counters map[string]int64) singboxDelta {
	out := singboxDelta{
		inbounds: map[string][2]int64{},
		users:    map[string][2]int64{},
	}
	if !a.seen {
		a.seen = true
		a.last = map[string]int64{}
		for name, v := range counters {
			a.last[name] = v
		}
		return out
	}
	for name, v := range counters {
		last, ok := a.last[name]
		var d int64
		if !ok || v < last {
			d = v
		} else {
			d = v - last
		}
		a.last[name] = v
		if d == 0 {
			continue
		}
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[2] != "traffic" {
			continue
		}
		var dir int
		switch parts[3] {
		case "uplink":
			dir = 0
		case "downlink":
			dir = 1
		default:
			continue
		}
		switch parts[0] {
		case "inbound":
			cur := out.inbounds[parts[1]]
			cur[dir] += d
			out.inbounds[parts[1]] = cur
		case "user":
			cur := out.users[parts[1]]
			cur[dir] += d
			out.users[parts[1]] = cur
		}
	}
	return out
}
