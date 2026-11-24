package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// v0.1.9：轻量节点后端切片 8——中转投影代收代写。
//
// 覆盖：
//   - 版本断言 0.1.9（main_test.go 已有，见 TestVersion）。
//   - validateRelayToml：好配置过；无 [[endpoints]] 拒；括号／引号
//     不配对拒。
//   - relayApplier.apply：好配置 → 原子写盘 0644＋重启一次；坏配置 →
//     不写盘、不重启；本机没装 realm → 拒绝、不写盘。
//   - 配置默认值：RealmConfigPath／RealmBin 为空时填默认路径。
//   - POST /relay-config：GET 405；空 body 400；applier 报错 → 500；
//     好配置 → 200 且 applier 收到全文；没配 applier → 503。
//   - 真重启（systemctl／pkill＋nohup 起 realm）不测：沙箱里没 realm
//     二进制，重启走测试桩；真机验收时再验。

const goodRelayToml019 = "[network]\nno_tcp = false\nuse_udp = true\n\n[[endpoints]]\nlisten = \"0.0.0.0:30004\"\nremote = \"203.0.113.1:443\"\n"

func TestValidateRelayToml019(t *testing.T) {
	if err := validateRelayToml([]byte(goodRelayToml019)); err != nil {
		t.Fatalf("好配置应通过：%v", err)
	}
	if err := validateRelayToml([]byte("[network]\nuse_udp = false\n")); err == nil || !strings.Contains(err.Error(), "[[endpoints]]") {
		t.Fatalf("无 [[endpoints]] 应拒，实际 %v", err)
	}
	if err := validateRelayToml([]byte("[[endpoints]\nlisten = \"0.0.0.0:30004\"\n")); err == nil || !strings.Contains(err.Error(), "不配对") {
		t.Fatalf("方括号不配对应拒，实际 %v", err)
	}
	if err := validateRelayToml([]byte("[[endpoints]]\nlisten = \"0.0.0.0:30004\n")); err == nil || !strings.Contains(err.Error(), "引号") {
		t.Fatalf("引号不配对应拒，实际 %v", err)
	}
}

func TestRelayApplierApply019(t *testing.T) {
	dir := t.TempDir()
	// 假 realm 二进制（只用来过 Stat 检查，不真跑；放 bin/ 下，
	// 别跟配置目录 realm/ 撞名）。
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("建 bin 目录失败：%v", err)
	}
	bin := filepath.Join(binDir, "realm")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("写假 realm 失败：%v", err)
	}
	cfgPath := filepath.Join(dir, "realm", "config.toml")
	restarts := 0
	a := newRelayApplier(cfgPath, bin)
	a.restart = func() error { restarts++; return nil }

	if err := a.apply([]byte(goodRelayToml019)); err != nil {
		t.Fatalf("好配置 apply 应成功：%v", err)
	}
	if restarts != 1 {
		t.Fatalf("好配置应重启 1 次，实际 %d 次", restarts)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil || string(got) != goodRelayToml019 {
		t.Fatalf("写盘内容不对：%q err=%v", string(got), err)
	}
	if st, err := os.Stat(cfgPath); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("写盘权限应 0644，实际 %v err=%v", st.Mode(), err)
	}

	// 坏配置：不写盘、不重启。
	restarts = 0
	badPath := filepath.Join(dir, "realm2", "config.toml")
	b := newRelayApplier(badPath, bin)
	b.restart = func() error { restarts++; return nil }
	if err := b.apply([]byte("[network]\nuse_udp = false\n")); err == nil {
		t.Fatal("坏配置 apply 应失败")
	}
	if restarts != 0 {
		t.Fatalf("坏配置不应重启，实际 %d 次", restarts)
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Fatalf("坏配置不应写盘，实际文件已存在")
	}
}

func TestRelayApplierNoRealm019(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "realm", "config.toml")
	a := newRelayApplier(cfgPath, filepath.Join(dir, "no-such-realm"))
	a.restart = func() error { return nil }
	err := a.apply([]byte(goodRelayToml019))
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("本机没装 realm 应拒（not installed），实际 %v", err)
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatal("没装 realm 时不应写盘")
	}
}

func TestRelayConfigDefaults019(t *testing.T) {
	c := &Config{}
	c.applyDefaults(t.TempDir())
	if c.RealmConfigPath != defaultRealmConfigPath {
		t.Fatalf("RealmConfigPath 默认应为 %s，实际 %s", defaultRealmConfigPath, c.RealmConfigPath)
	}
	if c.RealmBin != defaultRealmBin {
		t.Fatalf("RealmBin 默认应为 %s，实际 %s", defaultRealmBin, c.RealmBin)
	}
}

// testRelayControl 起一个带 fake applyRelay 的控制面（ephemeral 回环端口）。
func testRelayControl(t *testing.T, apply func([]byte) error) (string, *[]byte) {
	t.Helper()
	bin := fakeBinary(t, "sleep 300")
	sup := newSupervisor(bin, filepath.Join(t.TempDir(), "xray.json"))
	if err := sup.Start(); err != nil {
		t.Fatalf("supervisor Start: %v", err)
	}
	t.Cleanup(sup.Stop)
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	var got []byte
	wrapped := func(b []byte) error {
		got = append([]byte{}, b...)
		if apply != nil {
			return apply(b)
		}
		return nil
	}
	cs, err := newControlServer("127.0.0.1:0", sup, nil, func() error { return nil }, func() int { return 0 }, wrapped)
	if err != nil {
		t.Fatalf("newControlServer: %v", err)
	}
	addr, err := cs.Start()
	if err != nil {
		t.Fatalf("control Start: %v", err)
	}
	t.Cleanup(cs.Stop)
	return addr, &got
}

func postRelayConfig(t *testing.T, addr, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post("http://"+addr+"/relay-config", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /relay-config: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

// quoteJSON019 把字符串包成 JSON 字符串字面量（拼 POST body 用）。
func quoteJSON019(s string) string {
	return strconv.Quote(s)
}

var errTestRelay = errors.New("test relay apply failure")

func TestControlRelayConfig019(t *testing.T) {
	addr, got := testRelayControl(t, func(b []byte) error {
		if strings.Contains(string(b), "BAD") {
			return errTestRelay
		}
		return nil
	})
	// GET → 405。
	resp, err := http.Get("http://" + addr + "/relay-config")
	if err != nil {
		t.Fatalf("GET /relay-config: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET 应 405，实际 %d", resp.StatusCode)
	}
	// 空 body → 400。
	code, _ := postRelayConfig(t, addr, `{"config_toml":""}`)
	if code != http.StatusBadRequest {
		t.Fatalf("空 config_toml 应 400，实际 %d", code)
	}
	// applier 报错 → 500。
	code, m := postRelayConfig(t, addr, `{"config_toml":"BAD [[endpoints]]"}`)
	if code != http.StatusInternalServerError {
		t.Fatalf("applier 报错应 500，实际 %d：%v", code, m)
	}
	// 好配置 → 200，applier 收到全文。
	code, m = postRelayConfig(t, addr, `{"config_toml":`+quoteJSON019(goodRelayToml019)+`}`)
	if code != http.StatusOK || m["ok"] != true {
		t.Fatalf("好配置应 200 ok=true，实际 %d：%v", code, m)
	}
	if string(*got) != goodRelayToml019 {
		t.Fatalf("applier 收到的内容不对：%q", string(*got))
	}
}

// TestControlRelayConfigNoApplier019 没配 applier → 503。
func TestControlRelayConfigNoApplier019(t *testing.T) {
	bin := fakeBinary(t, "sleep 300")
	sup := newSupervisor(bin, filepath.Join(t.TempDir(), "xray.json"))
	if err := sup.Start(); err != nil {
		t.Fatalf("supervisor Start: %v", err)
	}
	t.Cleanup(sup.Stop)
	waitFor(t, 5*time.Second, "xray to start", sup.IsRunning)
	cs, err := newControlServer("127.0.0.1:0", sup, nil, func() error { return nil }, func() int { return 0 }, nil)
	if err != nil {
		t.Fatalf("newControlServer: %v", err)
	}
	addr, err := cs.Start()
	if err != nil {
		t.Fatalf("control Start: %v", err)
	}
	t.Cleanup(cs.Stop)
	code, _ := postRelayConfig(t, addr, `{"config_toml":`+quoteJSON019(goodRelayToml019)+`}`)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("没配 applier 应 503，实际 %d", code)
	}
}
