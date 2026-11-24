package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ---------- 中转投影代收代写（v0.1.9，切片 8） ----------
//
// 中转机与节点后端同机时，面板不直接写 realm 的 config.toml，改走
// 本 agent 的本地控制面：POST /relay-config（见 control.go）收面板
// 渲染好的完整 config.toml，校验、原子写盘、重启 realm 生效。
//
// 安全：只在控制面收（loopback，见 newControlServer 的回环校验），
// 不暴露公网；realm 没装在这台机上时直接拒绝（不凭空建 config.toml）；
// 校验不过不写盘、不重启（fail-closed）；写盘 0644，与面板的
// writeConfigTomlAtomic 同权限。

// defaultRealmConfigPath 是 realm config.toml 的默认位置（与面板的
// RealmDir 默认值 /etc/realm 一致）。
const defaultRealmConfigPath = "/etc/realm/config.toml"

// defaultRealmBin 是 realm 二进制的默认位置（与面板 restartRealm
// 用的路径一致）。
const defaultRealmBin = "/usr/local/bin/realm"

// relayApplier 收面板渲染好的 config.toml、写盘并重启 realm。
type relayApplier struct {
	configPath string
	binPath    string
	// restart 测试桩：非空时用它代替真重启（默认走 restartRealmProcess）。
	restart func() error
}

func newRelayApplier(configPath, binPath string) *relayApplier {
	if configPath == "" {
		configPath = defaultRealmConfigPath
	}
	if binPath == "" {
		binPath = defaultRealmBin
	}
	return &relayApplier{configPath: configPath, binPath: binPath}
}

// apply 校验 → 原子写盘 → 重启 realm。realm 没装在这台机上时拒绝。
func (a *relayApplier) apply(toml []byte) error {
	if err := validateRelayToml(toml); err != nil {
		return err
	}
	if _, err := os.Stat(a.binPath); err != nil {
		if _, err2 := os.Stat("/etc/systemd/system/realm.service"); err2 != nil {
			return fmt.Errorf("realm is not installed on this node")
		}
	}
	if err := writeFileAtomic(a.configPath, toml, 0o644); err != nil {
		return fmt.Errorf("write realm config: %w", err)
	}
	if a.restart != nil {
		return a.restart()
	}
	return restartRealmProcess(a.binPath, a.configPath)
}

// validateRelayToml 简易 TOML 校验（与面板 validateConfigToml 同口径：
// 方括号／引号配对＋含 [[endpoints]]；无 endpoint 的配置 realm 会
// panic，绝不收）。
func validateRelayToml(data []byte) error {
	depth := 0
	inStr := false
	for _, r := range string(data) {
		switch {
		case r == '"' && depth >= 0:
			inStr = !inStr
		case !inStr && r == '[':
			depth++
		case !inStr && r == ']':
			depth--
			if depth < 0 {
				return fmt.Errorf("config.toml 方括号不配对")
			}
		}
	}
	if depth != 0 || inStr {
		return fmt.Errorf("config.toml 括号/引号不配对")
	}
	if !strings.Contains(string(data), "[[endpoints]]") {
		return fmt.Errorf("config.toml 没有 [[endpoints]] 段")
	}
	return nil
}

func hasSystemdAgent() bool {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return false
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func realmRunningAgent() bool {
	if hasSystemdAgent() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "realm").Run() == nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "pgrep", "-x", "realm").Run() == nil
}

// restartRealmProcess 重启 realm：优先 systemctl，无 systemd 时 pkill +
// nohup 兜底（与面板 restartRealm 同款；日志超 10MB 不在这里轮转，
// 面板侧 rotateLogIfLarge 管那份日志，agent 只追加）。
func restartRealmProcess(binPath, configPath string) error {
	if hasSystemdAgent() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "systemctl", "restart", "realm").Run(); err != nil {
			return fmt.Errorf("systemctl restart realm 失败：%v", err)
		}
		time.Sleep(time.Second)
		if !realmRunningAgent() {
			return fmt.Errorf("realm 重启后没跑起来")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = exec.CommandContext(ctx, "pkill", "-x", "realm").Run()
	cancel()
	time.Sleep(time.Second)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	_ = exec.CommandContext(ctx2, "pkill", "-9", "-x", "realm").Run()
	cancel2()
	cmd := exec.Command("nohup", binPath, "-c", configPath)
	if f, err := os.OpenFile("/var/log/realm.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		defer f.Close()
		cmd.Stdout = f
		cmd.Stderr = f
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 realm 失败：%v", err)
	}
	time.Sleep(time.Second)
	if !realmRunningAgent() {
		return fmt.Errorf("realm 启动后没跑起来")
	}
	return nil
}