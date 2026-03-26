package main

import "testing"

func TestDebugLog_PrintfStyleDoesNotPanic(t *testing.T) {
	orig := Debug
	Debug = true
	t.Cleanup(func() { Debug = orig })

	// Should not panic even though slog doesn't do printf formatting.
	debugLogf("x=%s y=%d", "a", 1)
}
