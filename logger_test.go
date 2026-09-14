//go:build !lite
// +build !lite

package main

import (
	"log/slog"
	"testing"
)

func TestDebugLog_KVStyleDoesNotPanic(t *testing.T) {
	orig := Debug
	Debug = true
	t.Cleanup(func() { Debug = orig })

	// Should not panic with slog kv style.
	debugLog("test message", "key", "value", "count", 1)
}

func TestSetLogLevel_DebugReachesBothSwitches(t *testing.T) {
	origEnv, origLevel, origDebug := debugFromEnv, logLevel.Level(), Debug
	t.Cleanup(func() {
		debugFromEnv = origEnv
		logLevel.Set(origLevel)
		Debug = origDebug
	})

	debugFromEnv = false

	// 配置文件里写 logLevel=debug：slog 级别和 debugLog 的开关都得打开，
	// 只开前者的话 debugLog() 一行都出不来，配置等于没生效。
	setLogLevel("debug")
	if logLevel.Level() != slog.LevelDebug {
		t.Fatalf("slog level = %v, want DEBUG", logLevel.Level())
	}
	if !Debug {
		t.Fatal("Debug flag not enabled by logLevel=debug")
	}

	setLogLevel("info")
	if Debug {
		t.Fatal("Debug flag should be off at info level")
	}

	// DEBUG=1 单独使用也必须真的出调试日志，否则环境变量是摆设
	debugFromEnv = true
	setLogLevel("info")
	if logLevel.Level() != slog.LevelDebug {
		t.Fatalf("DEBUG=1 did not raise slog level, got %v", logLevel.Level())
	}
}
