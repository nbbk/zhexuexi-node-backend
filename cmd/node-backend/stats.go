package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Slice 4: traffic metering from Xray QueryStats.
//
// The agent reads counters through the Xray binary's own `api`
// subcommand (`xray api statsquery`), the same route slice 3 uses
// for adu/rmu: no grpc/protobuf dependency, standard library only.
// Verified against the pinned Xray 26.11.9:
//
//	xray api statsquery --server=127.0.0.1:10085 -pattern "" [-t=10]
//
// prints one JSON document:
//
//	{"stat": [{"name": "inbound>>>reality-443>>>traffic>>>uplink",
//	            "value": 12345}, ...]}
//
// Counters with no traffic yet are listed with the `value` field
// omitted (read as 0), and counters that never carried traffic do
// not exist at all (user>>> counters are created lazily on the
// first connection, so a missing counter at baseline means 0).
// A dead API makes the subcommand exit non-zero, so failures are
// detectable and the reporter treats the window as failed.

// statsSample is one QueryStats snapshot: counter name -> value.
type statsSample map[string]int64

// statsQueryResult is the JSON shape `xray api statsquery` prints.
type statsQueryResult struct {
	Stat []struct {
		Name  string `json:"name"`
		Value *int64 `json:"value"`
	} `json:"stat"`
}

// parseStatsquery parses statsquery output into a sample. A missing
// value means the counter exists but never counted: 0.
func parseStatsquery(out []byte) (statsSample, error) {
	var res statsQueryResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("parse statsquery output: %w", err)
	}
	sample := statsSample{}
	for _, s := range res.Stat {
		if s.Name == "" {
			continue
		}
		var v int64
		if s.Value != nil {
			v = *s.Value
		}
		sample[s.Name] = v
	}
	return sample, nil
}

// statsClient reads Xray counters.
type statsClient interface {
	// QueryStats returns the current counter snapshot. It must fail
	// when Xray is unreachable, so a failed window is never
	// reported as a zero-traffic window.
	QueryStats(ctx context.Context, serverAddr string) (statsSample, error)
}

// cliStatsClient implements statsClient by shelling out to
// `xray api statsquery` (same binary the supervisor runs). One
// subprocess per 60 s reporting cycle.
type cliStatsClient struct {
	xrayPath string
}

var statsTimeoutSec = 10

// QueryStats runs one statsquery with an empty pattern (all
// counters) and parses the JSON document it prints.
func (c *cliStatsClient) QueryStats(ctx context.Context, serverAddr string) (statsSample, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(statsTimeoutSec+5)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.xrayPath, "api", "statsquery",
		"--server="+serverAddr, fmt.Sprintf("-t=%d", statsTimeoutSec), "-pattern", "")
	out, err := cmd.CombinedOutput()
	if err != nil {
		tail := strings.TrimSpace(string(out))
		if len(tail) > 500 {
			tail = tail[len(tail)-500:]
		}
		return nil, fmt.Errorf("xray api statsquery failed: %v: %s", err, tail)
	}
	return parseStatsquery(out)
}

// statsDelta is the per-window increment for one counter family.
type statsDelta struct {
	// users maps email -> [uplink, downlink] increments.
	users map[string][2]int64
	// inbounds maps inbound tag -> [uplink, downlink] increments.
	inbounds map[string][2]int64
}

// statsAccumulator turns snapshots into window deltas. It keeps the
// previous snapshot as the baseline; the first snapshot only seeds
// the baseline (no delta is reported for traffic before the agent
// started watching).
type statsAccumulator struct {
	prev     statsSample
	baseline bool
}

// delta computes this window's increments from sample.
//
//   - a counter missing from the baseline never counted before:
//     its baseline is 0, so the whole value is this window's delta
//     (counters are created lazily on first traffic);
//   - a counter that went down (Xray restarted, counters reset):
//     only the baseline is cleared, the delta is 0 for this window
//     — the reset is never subtracted back ("不扣回");
//   - the "api" inbound is skipped: it only carries the agent's own
//     API calls (adu/rmu/statsquery), never client traffic.
func (a *statsAccumulator) delta(sample statsSample) statsDelta {
	d := statsDelta{users: map[string][2]int64{}, inbounds: map[string][2]int64{}}
	if !a.baseline {
		a.prev = sample
		a.baseline = true
		return d
	}
	for name, cur := range sample {
		prev, ok := a.prev[name]
		if !ok {
			prev = 0
		}
		var inc int64
		if cur < prev {
			inc = 0 // counter reset: clear the baseline, never go negative
		} else {
			inc = cur - prev
		}
		if inc == 0 {
			continue
		}
		if email, dir, ok := parseUserCounter(name); ok {
			v := d.users[email]
			v[dir] = inc
			d.users[email] = v
			continue
		}
		if tag, dir, ok := parseInboundCounter(name); ok {
			if tag == "api" {
				continue
			}
			v := d.inbounds[tag]
			v[dir] = inc
			d.inbounds[tag] = v
			continue
		}
	}
	a.prev = sample
	return d
}

// parseUserCounter parses "user>>><email>>>>traffic>>><uplink|downlink>".
// The second return is 0 for uplink, 1 for downlink.
func parseUserCounter(name string) (email string, dir int, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
		return "", 0, false
	}
	switch parts[3] {
	case "uplink":
		return parts[1], 0, true
	case "downlink":
		return parts[1], 1, true
	default:
		return "", 0, false
	}
}

// parseInboundCounter parses
// "inbound>>><tag>>>>traffic>>><uplink|downlink>".
func parseInboundCounter(name string) (tag string, dir int, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || parts[0] != "inbound" || parts[2] != "traffic" {
		return "", 0, false
	}
	switch parts[3] {
	case "uplink":
		return parts[1], 0, true
	case "downlink":
		return parts[1], 1, true
	default:
		return "", 0, false
	}
}
