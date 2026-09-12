//go:build !lite && !windows
// +build !lite,!windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

const (
	// restartSupported 是否支持从 Web 端原地重启
	restartSupported = true
	// restartMethodName 重启机制名称（前端据此展示说明）
	restartMethodName = "exec-in-place"
)

// restartInPlace 用 exec 原地替换进程映像。
//
// 为什么选它而不是 tableflip 那种 fork+exec 传 fd：
//   - exec 保持 PID 不变，systemd / 容器 / supervisor 都视为"同一次启动"，
//     不会因为主进程退出而拆掉 cgroup、也不会误判崩溃而额外拉一个实例；
//   - fork+exec 零停机，但需要调用方在 systemd unit 里配置 PIDFile 才能不被误判，
//     对 crproxy 这种"手动点一下重启"的场景不值当。
//
// 代价：调用前已经通过 restartShutdownFn 优雅关闭（等待在途请求），
// 因此只会有一段很短的端口空窗期。
func restartInPlaceOS(exe string, args []string) error {
	argv := make([]string, 0, len(args))
	argv = append(argv, exe)
	if len(args) > 1 {
		argv = append(argv, args[1:]...)
	}
	if err := syscall.Exec(exe, argv, os.Environ()); err != nil {
		return fmt.Errorf("exec %s failed: %w", exe, err)
	}
	return nil
}
