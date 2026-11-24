package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Slice 4: traffic reporting (POST /api/v1/node/traffic, every 60 s,
// piggybacked on the config pull cycle) with a local spool for
// offline replay. Field names are the panel contract and must not
// change: node_id, window_start, window_end, users (with user_key /
// up / down / inbound_tag), inbounds, online, health.
//
//   - users rows are per (user, inbound_tag). Xray's user>>> counters
//     are global per user, not per inbound, so a user assigned to
//     several VLESS inbounds is attributed to the first assigned
//     inbound in panel order (in practice the REALITY inbound: the
//     XHTTP inbound is a server-only fallback that never appears in
//     subscriptions, so it carries no client traffic). The per-inbound
//     totals in `inbounds` come from inbound>>> counters and are
//     exact; they are the authoritative per-inbound numbers.
//   - online[].ips is empty in this slice: Xray stats do not carry
//     IP addresses, and no data is ever fabricated — the panel
//     treats an empty list as "unknown".
// Slice 5: sing-box rows come from the V2Ray API stats service
// (build plan §9.4): per-inbound counters
// (inbound>>><tag>>>>traffic>>>uplink/downlink) and per-user
// counters (user>>><name>>>>traffic>>>uplink/downlink, name =
// the user's email). Both are cumulative; the reporter turns them
// into per-window deltas with singboxCounterAccumulator, in the
// same shape as the Xray rows above, so sing-box traffic enters
// the same quota and limit enforcement as Xray traffic.
//   - health.xray_restarts counts supervisor relaunches since the
//     agent started (crash recovery + config restarts); the initial
//     start is not a restart, so a healthy node reports 0, and an
//     agent restart resets it to 0. health.singbox_restarts is the
//     same counter for the sing-box supervisor.

// trafficUserRow is one per-user window increment.
type trafficUserRow struct {
	UserKey    string `json:"user_key"`
	Up         int64  `json:"up"`
	Down       int64  `json:"down"`
	InboundTag string `json:"inbound_tag"`
}

// trafficInboundRow is one per-inbound window increment.
type trafficInboundRow struct {
	InboundTag string `json:"inbound_tag"`
	Up         int64  `json:"up"`
	Down       int64  `json:"down"`
}

// trafficOnlineRow is one online user. IPs is empty in slice 4 (see above).
type trafficOnlineRow struct {
	UserKey string   `json:"user_key"`
	IPs     []string `json:"ips"`
}

// trafficHealth is the piggybacked health block.
type trafficHealth struct {
	AgentVersion    string  `json:"agent_version"`
	XrayVersion     string  `json:"xray_version"`
	XrayRunning     bool    `json:"xray_running"`
	XrayRestarts    int     `json:"xray_restarts"`
	SingboxVersion  string  `json:"singbox_version"`
	SingboxRunning  bool    `json:"singbox_running"`
	SingboxRestarts int     `json:"singbox_restarts"`
	ConfigVersion   int     `json:"config_version"`
	LastError       string  `json:"last_error"`
	CPUPercent      float64 `json:"cpu_percent"`
	MemMB           float64 `json:"mem_mb"`
}

// trafficReport is one POST /api/v1/node/traffic body. The panel
// deduplicates by (node_id, window_start, window_end), so replaying
// a window is safe.
type trafficReport struct {
	NodeID      int                 `json:"node_id"`
	WindowStart int64               `json:"window_start"`
	WindowEnd   int64               `json:"window_end"`
	Users       []trafficUserRow    `json:"users"`
	Inbounds    []trafficInboundRow `json:"inbounds"`
	Online      []trafficOnlineRow  `json:"online"`
	Health      trafficHealth       `json:"health"`
}

// spoolMaxAge is how long an unconfirmed window is kept: older
// windows are dropped and logged, never replayed (build plan §6.5).
const spoolMaxAge = 24 * time.Hour

// loadSpool reads the spool file. A missing file means no pending
// windows, not an error.
func loadSpool(path string) ([]trafficReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read spool %s: %w", path, err)
	}
	var windows []trafficReport
	if err := json.Unmarshal(data, &windows); err != nil {
		return nil, fmt.Errorf("parse spool %s: %w", path, err)
	}
	return windows, nil
}

// saveSpool writes windows to the spool file (0600, atomic rename).
func saveSpool(path string, windows []trafficReport) error {
	data, err := json.Marshal(windows)
	if err != nil {
		return fmt.Errorf("encode spool: %w", err)
	}
	return writeFileAtomic(path, data, 0o600)
}

// pruneSpool drops windows older than spoolMaxAge (judged by
// window_end) and reports how many were dropped.
func pruneSpool(windows []trafficReport, now time.Time) ([]trafficReport, int) {
	cutoff := now.Add(-spoolMaxAge).Unix()
	kept := windows[:0]
	dropped := 0
	for _, w := range windows {
		if w.WindowEnd < cutoff {
			dropped++
			continue
		}
		kept = append(kept, w)
	}
	return kept, dropped
}

// persistSpool stores windows, or removes the spool file when there
// is nothing pending (a missing file and an empty file mean the same).
func persistSpool(path string, windows []trafficReport) error {
	if len(windows) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove spool %s: %w", path, err)
		}
		return nil
	}
	return saveSpool(path, windows)
}

// trafficReporter collects one 60 s window per tick and reports it.
// It is the only writer of the spool file.
type trafficReporter struct {
	cfg     *Config
	client  *http.Client
	stats   statsClient
	sup     *supervisor
	sbSup   *supervisor // sing-box supervisor (slice 5); nil = no sing-box
	applier *configApplier

	mu          sync.Mutex
	acc         statsAccumulator
	sbAcc       singboxCounterAccumulator
	windowStart time.Time
	lastErr     string
	cpuPrev     *cpuSample
}

// newTrafficReporter builds a reporter. stats may be nil for the
// default cliStatsClient (tests inject a fake). sbSup may be nil.
func newTrafficReporter(cfg *Config, client *http.Client, sup *supervisor, sbSup *supervisor, applier *configApplier, stats statsClient) *trafficReporter {
	if stats == nil {
		stats = &cliStatsClient{xrayPath: cfg.XrayPath}
	}
	return &trafficReporter{
		cfg: cfg, client: client, stats: stats, sup: sup, sbSup: sbSup, applier: applier,
		windowStart: time.Now(),
	}
}

// serverAddr is the Xray API address for stats queries.
func (r *trafficReporter) serverAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", r.cfg.APIPort)
}

// tick collects the window ending at now and reports it: spool
// replay first (oldest first), then the current window. On any
// failure the unconfirmed windows stay spooled and the error is
// returned; the run loop logs it and retries next cycle. The
// accumulator baseline is only advanced by a successful stats read,
// so traffic from a failed stats window is picked up by the next
// successful read (attributed to that window, never lost and never
// double-counted).
func (r *trafficReporter) tick(now time.Time) error {
	r.mu.Lock()
	windowStart := r.windowStart
	r.windowStart = now
	r.mu.Unlock()

	delta := statsDelta{users: map[string][2]int64{}, inbounds: map[string][2]int64{}}
	statsErr := error(nil)
	if r.sup.IsRunning() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(statsTimeoutSec+5)*time.Second)
		sample, err := r.stats.QueryStats(ctx, r.serverAddr())
		cancel()
		if err != nil {
			statsErr = err
		} else {
			r.mu.Lock()
			delta = r.acc.delta(sample)
			r.mu.Unlock()
		}
	} else {
		// Xray is down: there is nothing to count, but the report
		// still goes out — it is how the panel learns within 60 s
		// that Xray stopped and what the last error was.
		statsErr = fmt.Errorf("xray is not running")
	}
	if statsErr != nil {
		r.setLastErr(statsErr)
		log.Printf("traffic stats unavailable for this window (%v); reporting health only", statsErr)
	}

	users, targets, _ := r.applier.snapshot()
	rep := r.buildReport(windowStart, now, delta, users, targets)
	// Slice 5: sing-box rows come from the V2Ray API stats service:
	// per-inbound counters and per-user counters (name = email).
	// A stats failure only drops the sing-box rows for this window;
	// it never fails the tick (the Xray delta above is reported
	// regardless). User names are matched back to the snapshot by
	// the same name rule the renderer uses (email, else user ID).
	if r.sbSup != nil && r.sbSup.IsRunning() {
		counters, err := querySingboxStats(defaultSingboxV2RayAddr)
		if err != nil {
			log.Printf("sing-box stats unavailable for this window (%v); no sing-box rows", err)
		} else {
			r.mu.Lock()
			sbDelta := r.sbAcc.delta(counters)
			r.mu.Unlock()
			for tag, v := range sbDelta.inbounds {
				if v[0] == 0 && v[1] == 0 {
					continue
				}
				rep.Inbounds = append(rep.Inbounds, trafficInboundRow{InboundTag: tag, Up: v[0], Down: v[1]})
			}
			for name, v := range sbDelta.users {
				if v[0] == 0 && v[1] == 0 {
					continue
				}
				key, tag := userKeyForSingboxName(name, users, targets)
				rep.Users = append(rep.Users, trafficUserRow{UserKey: key, Up: v[0], Down: v[1], InboundTag: tag})
			}
			sort.Slice(rep.Inbounds, func(i, j int) bool {
				return rep.Inbounds[i].InboundTag < rep.Inbounds[j].InboundTag
			})
			sort.Slice(rep.Users, func(i, j int) bool {
				if rep.Users[i].UserKey != rep.Users[j].UserKey {
					return rep.Users[i].UserKey < rep.Users[j].UserKey
				}
				return rep.Users[i].InboundTag < rep.Users[j].InboundTag
			})
		}
	}
	if err := r.postWithReplay(rep, now); err != nil {
		r.setLastErr(err)
		return err
	}
	// Only a fully successful cycle clears the last error: a stats
	// failure this tick stays visible in health until a later tick
	// reads stats and reports cleanly.
	if statsErr == nil {
		r.clearLastErr()
	}
	return nil
}

// buildReport assembles one window from a delta and the last applied
// user set. Only rows with traffic are emitted; an idle window
// reports empty users/inbounds arrays (never null).
func (r *trafficReporter) buildReport(windowStart, windowEnd time.Time, delta statsDelta, users map[string]configUser, targets []vlessTarget) trafficReport {
	rep := trafficReport{
		NodeID:      r.cfg.NodeID,
		WindowStart: windowStart.Unix(),
		WindowEnd:   windowEnd.Unix(),
		Users:       []trafficUserRow{},
		Inbounds:    []trafficInboundRow{},
		Online:      []trafficOnlineRow{},
		Health:      r.buildHealth(),
	}
	for email, v := range delta.users {
		if v[0] == 0 && v[1] == 0 {
			continue
		}
		u, known := users[email]
		key := userKeyForEmail(email)
		tag := ""
		if known {
			key = userKey(u)
			tag = attributeInbound(u, targets)
		}
		rep.Users = append(rep.Users, trafficUserRow{
			UserKey: key, Up: v[0], Down: v[1], InboundTag: tag,
		})
	}
	sort.Slice(rep.Users, func(i, j int) bool {
		if rep.Users[i].UserKey != rep.Users[j].UserKey {
			return rep.Users[i].UserKey < rep.Users[j].UserKey
		}
		return rep.Users[i].InboundTag < rep.Users[j].InboundTag
	})
	for tag, v := range delta.inbounds {
		if v[0] == 0 && v[1] == 0 {
			continue
		}
		rep.Inbounds = append(rep.Inbounds, trafficInboundRow{
			InboundTag: tag, Up: v[0], Down: v[1],
		})
	}
	sort.Slice(rep.Inbounds, func(i, j int) bool {
		return rep.Inbounds[i].InboundTag < rep.Inbounds[j].InboundTag
	})
	return rep
}

// userKeyForSingboxName maps a sing-box stats user name back to
// the panel user_key and the inbound_tag for its traffic row. The
// name is the renderer's singboxUserName (email, else user ID), so
// it is looked up in the snapshot by email first, then by user ID.
// An unknown name still yields a row (derived key, no tag): the
// traffic must survive, and the panel can still match it.
func userKeyForSingboxName(name string, users map[string]configUser, targets []vlessTarget) (string, string) {
	if u, ok := users[name]; ok {
		return userKey(u), attributeInbound(u, targets)
	}
	for _, u := range users {
		if u.UserID == name {
			return userKey(u), attributeInbound(u, targets)
		}
	}
	return userKeyForEmail(name), ""
}

// attributeInbound picks the inbound_tag for one user's row: the
// first assigned VLESS inbound in panel order. A user with no
// inbounds field is assigned to all of them; a user assigned only
// to non-Xray inbounds (or with no targets at all) gets "".
func attributeInbound(u configUser, targets []vlessTarget) string {
	for _, t := range targets {
		if len(u.Inbounds) == 0 || slicesContains(u.Inbounds, t.Tag) {
			return t.Tag
		}
	}
	return ""
}

// buildHealth assembles the health block. last_error is the most
// recent apply error while Xray is up; when Xray is down it is the
// supervisor's last error (the reason it stopped), falling back to
// the reporter's last error in either case.
func (r *trafficReporter) buildHealth() trafficHealth {
	st := r.sup.Status()
	lastErr := ""
	if !st.Running {
		lastErr = st.LastErr
	}
	if lastErr == "" {
		lastErr = r.applier.lastError()
	}
	if lastErr == "" {
		r.mu.Lock()
		lastErr = r.lastErr
		r.mu.Unlock()
	}
	health := trafficHealth{
		AgentVersion:   Version,
		XrayVersion:    XrayVersion,
		XrayRunning:    st.Running,
		XrayRestarts:   st.Restarts,
		SingboxVersion: SingboxVersion,
		ConfigVersion:  r.applier.appliedVersion(),
		LastError:      lastErr,
	}
	if r.sbSup != nil {
		sbSt := r.sbSup.Status()
		health.SingboxRunning = sbSt.Running
		health.SingboxRestarts = sbSt.Restarts
		// sing-box is expected down when it has no inbounds; only
		// surface its last error when it should be running but is not.
		if health.LastError == "" && !sbSt.Running && sbSt.LastErr != "" && len(r.applier.singboxTags()) > 0 {
			health.LastError = "sing-box: " + sbSt.LastErr
		}
	}
	cpu, mem := r.sampleProc()
	health.CPUPercent = cpu
	health.MemMB = mem
	return health
}

// postWithReplay posts spooled windows oldest-first, then rep. A
// failure stops the replay (order is preserved) and the failing
// window plus everything after it stays spooled with rep appended.
// Windows older than 24 h are dropped before replay and logged.
func (r *trafficReporter) postWithReplay(rep trafficReport, now time.Time) error {
	pending, err := loadSpool(r.cfg.SpoolPath)
	if err != nil {
		log.Printf("spool unreadable (%v); keeping only the current window", err)
		pending = nil
	}
	pending, dropped := pruneSpool(pending, now)
	if dropped > 0 {
		log.Printf("spool: dropped %d window(s) older than 24h without confirmation", dropped)
		r.setLastErr(fmt.Errorf("spool dropped %d window(s) older than 24h", dropped))
	}
	for i, w := range pending {
		if err := postTraffic(r.client, r.cfg.PanelURL, w); err != nil {
			rest := append(append([]trafficReport{}, pending[i:]...), rep)
			if perr := persistSpool(r.cfg.SpoolPath, rest); perr != nil {
				log.Printf("spool write failed (%v); %d window(s) kept in memory only", perr, len(rest))
			}
			return fmt.Errorf("replay window %d failed: %w", i, err)
		}
	}
	if err := postTraffic(r.client, r.cfg.PanelURL, rep); err != nil {
		if perr := persistSpool(r.cfg.SpoolPath, []trafficReport{rep}); perr != nil {
			log.Printf("spool write failed (%v); current window kept in memory only", perr)
		}
		return fmt.Errorf("post current window failed: %w", err)
	}
	if len(pending) > 0 {
		if err := persistSpool(r.cfg.SpoolPath, nil); err != nil {
			log.Printf("spool clear failed: %v", err)
		}
	}
	return nil
}

func (r *trafficReporter) setLastErr(err error) {
	r.mu.Lock()
	r.lastErr = err.Error()
	r.mu.Unlock()
}

func (r *trafficReporter) clearLastErr() {
	r.mu.Lock()
	r.lastErr = ""
	r.mu.Unlock()
}

// cpuSample is one /proc reading for CPU percent computation.
type cpuSample struct {
	ticks int64
	at    time.Time
}

// sampleProc reads this process's CPU and memory from /proc, best
// effort: any read failure returns 0, 0 (never fabricated). CPU
// percent is the delta of process jiffies over wall time since the
// previous sample; the first sample returns 0 (no baseline yet).
// CLK_TCK is 100 on Linux; the value is only used as a scale.
func (r *trafficReporter) sampleProc() (cpu float64, mem float64) {
	ticks, rssPages, err := readProcSelfStat()
	if err != nil {
		return 0, 0
	}
	mem = float64(rssPages) * float64(os.Getpagesize()) / (1024 * 1024)
	now := time.Now()
	r.mu.Lock()
	prev := r.cpuPrev
	r.cpuPrev = &cpuSample{ticks: ticks, at: now}
	r.mu.Unlock()
	if prev == nil {
		return 0, round1(mem)
	}
	wall := now.Sub(prev.at).Seconds()
	dTicks := ticks - prev.ticks
	if wall <= 0 || dTicks < 0 {
		return 0, round1(mem)
	}
	cpu = 100 * (float64(dTicks) / 100) / wall
	if max := float64(100 * runtime.NumCPU()); cpu > max {
		cpu = max
	}
	return round1(cpu), round1(mem)
}

func round1(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}

// readProcSelfStat parses /proc/self/stat: utime+stime (fields 14+15)
// in clock ticks and rss (field 24) in pages.
func readProcSelfStat() (ticks int64, rssPages int64, err error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, 0, err
	}
	// comm is parenthesised and may contain spaces; fields start
	// after the last ')'.
	rest := data
	if i := strings.LastIndexByte(string(data), ')'); i >= 0 {
		rest = data[i+2:]
	}
	fields := strings.Fields(string(rest))
	// fields[0] is state (field 3); utime is field 14 -> [11],
	// stime field 15 -> [12], rss field 24 -> [21].
	if len(fields) < 22 {
		return 0, 0, fmt.Errorf("/proc/self/stat has %d fields, want >= 22", len(fields))
	}
	utime, err := strconv.ParseInt(fields[11], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse utime: %w", err)
	}
	stime, err := strconv.ParseInt(fields[12], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse stime: %w", err)
	}
	rss, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse rss: %w", err)
	}
	return utime + stime, rss, nil
}
