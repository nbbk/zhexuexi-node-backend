package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Slice 3: hot user sync via the Xray gRPC API.
//
// The agent talks to Xray's HandlerService through the Xray binary's
// own `api` subcommand (`xray api adu` / `xray api rmu`) instead of
// speaking gRPC itself. Rationale (deliberate, see the report):
//   - zero new dependencies: the agent stays a static binary on the
//     standard library only; no grpc/protobuf/x-net in go.mod;
//   - the wire encoding (TypedMessage account type
//     "xray.proxy.vless.Account", AddUserOperation's repeated `users`
//     field) is Xray's own code, not a hand-rolled protobuf encoder
//     that would fail silently on a wrong field number or type name;
//   - verified against the pinned Xray 26.11.9: adu takes one JSON
//     document {"inbounds": [{"tag", "port", "protocol", "settings":
//     {"clients": [...], "decryption": "none"}}]} and reports
//     "Added N user(s) in total"; rmu takes emails per tag and
//     reports "Removed N user(s) in total". A dead API makes both
//     exit non-zero ("failed to dial"), so failures are detectable
//     and the applier can fall back to a full rewrite+restart.
// The cost is one subprocess spawn per inbound per pull cycle that
// actually changes users (60 s cadence, few users): negligible.
// The adu temp file holds UUIDs: mode 0600, deleted right after use.

// effectiveUsers is the set of panel users that belong in a VLESS
// inbound, keyed by email (the Xray user>>> stats key and the rmu
// key). Same filter as vlessClients: disabled users and users
// without a UUID are left out.
func effectiveUsers(users []configUser) map[string]configUser {
	out := map[string]configUser{}
	for _, u := range users {
		if u.Disabled || strings.TrimSpace(u.VLESSUUID) == "" {
			continue
		}
		out[u.Email] = u
	}
	return out
}

// userDiff is the delta between the applied user set and the new one,
// keyed by email. rotated is also listed in removed: a UUID rotation
// is applied as remove-then-add under the same email.
type userDiff struct {
	added   []configUser
	removed []string
	rotated []configUser
}

// diffUsers compares the applied set (old) with the new panel set.
func diffUsers(old, new map[string]configUser) userDiff {
	var d userDiff
	for email, nu := range new {
		if ou, ok := old[email]; !ok {
			d.added = append(d.added, nu)
		} else if ou.VLESSUUID != nu.VLESSUUID {
			d.removed = append(d.removed, email)
			d.rotated = append(d.rotated, nu)
		}
	}
	for email := range old {
		if _, ok := new[email]; !ok {
			d.removed = append(d.removed, email)
		}
	}
	return d
}

// usersEqual reports whether two effective user sets are identical
// (same emails, same UUIDs).
func usersEqual(a, b map[string]configUser) bool {
	if len(a) != len(b) {
		return false
	}
	for email, ua := range a {
		ub, ok := b[email]
		if !ok || ub.VLESSUUID != ua.VLESSUUID {
			return false
		}
	}
	return true
}

// vlessTarget is one rendered VLESS inbound that hot user changes
// apply to. Flow is per inbound: the reality inbound's flow
// (xtls-rprx-vision), empty for xhttp (XHTTP + Vision is invalid).
type vlessTarget struct {
	Tag  string
	Port int
	Flow string
}

// vlessTargets enumerates the VLESS inbounds a panel doc renders to,
// reusing renderVLESSInbound so the hot path and the render path can
// never disagree about which inbounds exist.
func vlessTargets(nc *nodeConfig) ([]vlessTarget, error) {
	var targets []vlessTarget
	for _, in := range nc.Inbounds {
		if !in.Enabled || in.Protocol != "vless" {
			continue
		}
		xb, skip, err := renderVLESSInbound(in, nil)
		if err != nil {
			return nil, fmt.Errorf("inbound %s: %w", in.InboundTag, err)
		}
		if skip {
			continue
		}
		flow := ""
		if strings.ToLower(in.Transport) == "reality" {
			flow = strings.TrimSpace(in.Flow)
		}
		targets = append(targets, vlessTarget{Tag: xb.Tag, Port: xb.Port, Flow: flow})
	}
	return targets, nil
}

// alterUser is one user as written into an adu document.
type alterUser struct {
	Email string
	UUID  string
	Flow  string
}

// alterClient applies user changes to a running Xray.
type alterClient interface {
	// AddUsers adds users to one inbound; it must fail unless every
	// user was added (a duplicate add is an error: the existing user
	// may carry a different UUID).
	AddUsers(ctx context.Context, serverAddr string, target vlessTarget, users []alterUser) error
	// RemoveUsers removes users from one inbound by email. Removing
	// an already-gone user is not an error: the end state (user
	// gone) already holds.
	RemoveUsers(ctx context.Context, serverAddr string, target vlessTarget, emails []string) error
}

// cliAlterClient implements alterClient by shelling out to
// `xray api adu` / `xray api rmu` (same binary the supervisor runs).
type cliAlterClient struct {
	xrayPath string
}

var (
	aduAddedRe    = regexp.MustCompile(`Added (\d+) user\(s\) in total`)
	rmuRemovedRe  = regexp.MustCompile(`Removed (\d+) user\(s\) in total`)
	aduTimeoutSec = 10
)

// runXrayAPI runs one `xray api` subcommand and returns its combined
// output. A non-zero exit is an error carrying the output tail.
func runXrayAPI(ctx context.Context, xrayPath string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, xrayPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		tail := strings.TrimSpace(string(out))
		if len(tail) > 500 {
			tail = tail[len(tail)-500:]
		}
		return string(out), fmt.Errorf("xray %s failed: %v: %s", strings.Join(args, " "), err, tail)
	}
	return string(out), nil
}

// AddUsers writes one adu document (all users for this inbound) to a
// 0600 temp file and runs `xray api adu` on it.
func (c *cliAlterClient) AddUsers(ctx context.Context, serverAddr string, target vlessTarget, users []alterUser) error {
	clients := make([]map[string]any, 0, len(users))
	for _, u := range users {
		entry := map[string]any{"id": u.UUID, "email": u.Email}
		if f := strings.TrimSpace(u.Flow); f != "" {
			entry["flow"] = f
		}
		clients = append(clients, entry)
	}
	doc := map[string]any{
		"inbounds": []map[string]any{{
			"tag":      target.Tag,
			"port":     target.Port,
			"protocol": "vless",
			"settings": map[string]any{"clients": clients, "decryption": "none"},
		}},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode adu document: %w", err)
	}
	tmp, err := os.CreateTemp("", ".adu-*.json")
	if err != nil {
		return fmt.Errorf("create adu temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod adu temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write adu temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close adu temp file: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(aduTimeoutSec+5)*time.Second)
	defer cancel()
	out, err := runXrayAPI(ctx, c.xrayPath, "api", "adu",
		"--server="+serverAddr, fmt.Sprintf("-t=%d", aduTimeoutSec), tmpName)
	if err != nil {
		return err
	}
	m := aduAddedRe.FindStringSubmatch(out)
	if m == nil {
		return fmt.Errorf("adu output did not report an added count: %q", strings.TrimSpace(out))
	}
	var added int
	if _, err := fmt.Sscanf(m[1], "%d", &added); err != nil {
		return fmt.Errorf("adu output count %q unreadable: %w", m[1], err)
	}
	if added != len(users) {
		return fmt.Errorf("adu added %d of %d users to %s (duplicate or rejected user?)", added, len(users), target.Tag)
	}
	return nil
}

// RemoveUsers runs `xray api rmu -tag=<tag> <emails...>` once for the
// inbound. A short count only warns: a user that is already gone is
// the desired end state.
func (c *cliAlterClient) RemoveUsers(ctx context.Context, serverAddr string, target vlessTarget, emails []string) error {
	args := []string{"api", "rmu", "--server=" + serverAddr,
		fmt.Sprintf("-t=%d", aduTimeoutSec), "-tag=" + target.Tag}
	args = append(args, emails...)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(aduTimeoutSec+5)*time.Second)
	defer cancel()
	out, err := runXrayAPI(ctx, c.xrayPath, args...)
	if err != nil {
		return err
	}
	if m := rmuRemovedRe.FindStringSubmatch(out); m != nil {
		var removed int
		if _, err := fmt.Sscanf(m[1], "%d", &removed); err == nil && removed != len(emails) {
			log.Printf("rmu removed %d of %d users from %s (rest were already gone)",
				removed, len(emails), target.Tag)
		}
	}
	return nil
}

// byInboundSets splits an effective user set per VLESS inbound tag:
// a user with an empty inbounds field belongs to every target, a
// user with a list only to the listed tags.
func byInboundSets(users map[string]configUser, targets []vlessTarget) map[string]map[string]configUser {
	out := map[string]map[string]configUser{}
	for _, t := range targets {
		set := map[string]configUser{}
		for email, u := range users {
			if len(u.Inbounds) == 0 || slicesContains(u.Inbounds, t.Tag) {
				set[email] = u
			}
		}
		out[t.Tag] = set
	}
	return out
}

// byInboundSetsEqual reports whether two per-inbound user sets agree
// on every tag in tags (same emails, same UUIDs per inbound).
func byInboundSetsEqual(a, b map[string]map[string]configUser, tags []string) bool {
	for _, tag := range tags {
		if !usersEqual(a[tag], b[tag]) {
			return false
		}
	}
	return true
}

// byInboundTags lists the tags present in either per-inbound set.
func byInboundTags(a, b map[string]map[string]configUser) []string {
	seen := map[string]bool{}
	var tags []string
	for _, m := range []map[string]map[string]configUser{a, b} {
		for tag := range m {
			if !seen[tag] {
				seen[tag] = true
				tags = append(tags, tag)
			}
		}
	}
	sort.Strings(tags)
	return tags
}

// applyUserDiff hot-applies the per-inbound user delta to every VLESS
// inbound: for each inbound, removes (deletions + rotations) first,
// then adds (additions + rotations). A user assigned to one inbound
// only moves there; a user assigned to all moves everywhere. Any
// failure aborts the diff; the caller falls back to a full
// rewrite+restart, so a half-applied diff never becomes the recorded
// state. Every non-empty diff logs exactly one hot-applied line.
func applyUserDiff(ctx context.Context, client alterClient, serverAddr string, targets []vlessTarget, oldSets, newSets map[string]map[string]configUser) error {
	if len(targets) == 0 {
		return nil
	}
	var added, removed, rotated int
	changed := false
	for _, t := range targets {
		d := diffUsers(oldSets[t.Tag], newSets[t.Tag])
		if len(d.added) == 0 && len(d.removed) == 0 {
			continue
		}
		changed = true
		if len(d.removed) > 0 {
			if err := client.RemoveUsers(ctx, serverAddr, t, d.removed); err != nil {
				return fmt.Errorf("remove users from %s: %w", t.Tag, err)
			}
		}
		toAdd := append(append([]configUser{}, d.added...), d.rotated...)
		if len(toAdd) > 0 {
			users := make([]alterUser, 0, len(toAdd))
			for _, u := range toAdd {
				users = append(users, alterUser{Email: u.Email, UUID: u.VLESSUUID, Flow: t.Flow})
			}
			if err := client.AddUsers(ctx, serverAddr, t, users); err != nil {
				return fmt.Errorf("add users to %s: %w", t.Tag, err)
			}
		}
		added += len(d.added)
		removed += len(d.removed) - len(d.rotated)
		rotated += len(d.rotated)
	}
	if changed {
		log.Printf("users hot-applied via AlterInbound: +%d -%d rotated=%d inbounds=%d",
			added, removed, rotated, len(targets))
	}
	return nil
}

// usersAndStructureFromRendered parses a rendered xray.json (the file
// on disk) and returns the user set it carries (email -> configUser,
// per VLESS inbound, plus the merged set over all inbounds) and the
// SHA-256 of the same config with the user lists stripped. The
// stripped SHA is the "structure" identity: two renders with the
// same inbounds/ports/REALITY settings but different users hash
// identically, so the applier can tell a user-only change
// (hot-apply) from a structural change (restart). The strip+marshal
// pipeline is the same one structureSHA applies to fresh renders,
// so disk and fresh values are comparable.
//
// The per-inbound sets matter: a user the disk file only carries in
// reality-443 must not be treated as present in xhttp-443 when the
// applier diffs after a restart, or a removal from one inbound
// would be silently skipped.
func usersAndStructureFromRendered(data []byte) (map[string]configUser, map[string]map[string]configUser, string, error) {
	var cfg xrayConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, nil, "", fmt.Errorf("parse rendered xray config: %w", err)
	}
	users := map[string]configUser{}
	byInbound := map[string]map[string]configUser{}
	for i := range cfg.Inbounds {
		in := &cfg.Inbounds[i]
		if in.Protocol != "vless" || in.Tag == "api" {
			continue
		}
		settings, ok := in.Settings.(map[string]any)
		if !ok {
			continue
		}
		clients, ok := settings["clients"].([]any)
		if !ok {
			continue
		}
		set := map[string]configUser{}
		for _, c := range clients {
			m, ok := c.(map[string]any)
			if !ok {
				continue
			}
			email, _ := m["email"].(string)
			id, _ := m["id"].(string)
			if email == "" || id == "" {
				continue
			}
			u := configUser{Email: email, VLESSUUID: id}
			users[email] = u
			set[email] = u
		}
		byInbound[in.Tag] = set
		settings["clients"] = []any{}
	}
	stripped, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, nil, "", fmt.Errorf("encode stripped xray config: %w", err)
	}
	sum := sha256.Sum256(stripped)
	return users, byInbound, hex.EncodeToString(sum[:]), nil
}

// structureSHA returns the stripped SHA of a freshly rendered config.
func structureSHA(rendered []byte) (string, error) {
	_, _, sha, err := usersAndStructureFromRendered(rendered)
	return sha, err
}
