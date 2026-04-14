//go:build !lite
// +build !lite

package main

import "testing"

func TestDebugLog_KVStyleDoesNotPanic(t *testing.T) {
	orig := Debug
	Debug = true
	t.Cleanup(func() { Debug = orig })

	// Should not panic with slog kv style.
	debugLog("test message", "key", "value", "count", 1)
}
