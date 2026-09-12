//go:build !lite && windows
// +build !lite,windows

package main

import "fmt"

const (
	// restartSupported Windows 没有 exec 语义，无法原地替换运行中的进程
	restartSupported = false
	// restartMethodName 重启机制名称
	restartMethodName = "unsupported"
)

// restartInPlace Windows 不支持原地重启：运行中的 exe 无法被替换，
// 也没有等价的 exec 语义，只能由服务管理器（如 NSSM / sc）重启。
func restartInPlaceOS(exe string, args []string) error {
	return fmt.Errorf("in-place restart is not supported on Windows; please restart the service manually")
}
