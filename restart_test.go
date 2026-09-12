//go:build !lite && !windows
// +build !lite,!windows

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// 环境探测：各种部署形态都要能识别出来
func TestDetectRestartEnvironment(t *testing.T) {
	cases := []struct {
		name        string
		env         map[string]string
		files       map[string]bool
		ppid        int
		wantKind    string
		wantInCont  bool
		wantSvcName string
	}{
		{
			name:        "kubernetes 优先于容器与 init 系统",
			env:         map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1", "POD_NAMESPACE": "registry", "INVOCATION_ID": "abc"},
			files:       map[string]bool{"/.dockerenv": true},
			wantKind:    envKubernetes,
			wantInCont:  true,
			wantSvcName: "registry",
		},
		{
			name:       "docker 容器",
			env:        map[string]string{"INVOCATION_ID": "abc"},
			files:      map[string]bool{"/.dockerenv": true},
			wantKind:   envDocker,
			wantInCont: true,
		},
		{
			name:     "systemd（INVOCATION_ID）",
			env:      map[string]string{"INVOCATION_ID": "abc"},
			wantKind: envSystemd,
		},
		{
			name:     "systemd（/run/systemd/system + 父进程是 1）",
			files:    map[string]bool{"/run/systemd/system": true},
			ppid:     1,
			wantKind: envSystemd,
		},
		{
			name:     "systemd 主机的终端进程不应误判为 systemd 服务",
			files:    map[string]bool{"/run/systemd/system": true},
			ppid:     54321,
			wantKind: envStandalone,
		},
		{
			name:     "launchd（父进程是 1）",
			env:      map[string]string{"XPC_SERVICE_NAME": "com.example.crproxy"},
			ppid:     1,
			wantKind: envLaunchd,
		},
		{
			name:     "macOS 终端里带着 XPC_SERVICE_NAME 也不应误判",
			env:      map[string]string{"XPC_SERVICE_NAME": "com.apple.Terminal"},
			ppid:     4242,
			wantKind: envStandalone,
		},
		{
			name:     "supervisor",
			env:      map[string]string{"SUPERVISOR_ENABLED": "1"},
			ppid:     999,
			wantKind: envSupervisor,
		},
		{
			name:     "独立进程",
			wantKind: envStandalone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldGetenv := restartGetenv
			oldExists := restartFileExists
			oldPPID := restartPPID
			restartGetenv = func(k string) string { return tc.env[k] }
			restartFileExists = func(p string) bool { return tc.files[p] }
			restartPPID = func() int { return tc.ppid }
			t.Cleanup(func() {
				restartGetenv = oldGetenv
				restartFileExists = oldExists
				restartPPID = oldPPID
			})

			got := detectRestartEnvironment()
			if got.Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", got.Kind, tc.wantKind)
			}
			if got.InContainer != tc.wantInCont {
				t.Errorf("inContainer = %v, want %v", got.InContainer, tc.wantInCont)
			}
			if got.ServiceName != tc.wantSvcName {
				t.Errorf("serviceName = %q, want %q", got.ServiceName, tc.wantSvcName)
			}
		})
	}
}

// 同一时刻只能有一次重启请求
func TestRequestRestartRejectsDuplicate(t *testing.T) {
	oldState := restartState
	oldProgress := updateProgress
	restartState = &restartTracker{}
	updateProgress = &updateTracker{stage: updateStageIdle}
	t.Cleanup(func() {
		restartState = oldState
		updateProgress = oldProgress
	})

	if !requestRestart() {
		t.Fatal("第一次重启请求应当被接受")
	}
	if requestRestart() {
		t.Error("重启进行中的重复请求应被拒绝")
	}
}

// 有更新正在下载时不允许重启，避免边下边换文件
func TestRequestRestartBlockedWhileUpdating(t *testing.T) {
	oldState := restartState
	oldProgress := updateProgress
	restartState = &restartTracker{}
	updateProgress = &updateTracker{stage: updateStageIdle}
	t.Cleanup(func() {
		restartState = oldState
		updateProgress = oldProgress
	})

	if !updateProgress.begin() {
		t.Fatal("准备失败：无法启动更新状态")
	}
	defer updateProgress.complete("")

	if requestRestart() {
		t.Error("更新进行中时不应接受重启请求")
	}
}

// 预检失败（新二进制跑不起来）时必须放弃重启，且服务保持存活：
// 既不能 exec，也不该走到关闭 HTTP 服务那一步。
func TestPerformRestartAbortsWhenNewBinaryIsBroken(t *testing.T) {
	oldState, oldDelay := restartState, restartDelay
	oldValidate, oldShutdown, oldExec := restartValidateFn, restartShutdownFn, restartInPlaceFn
	oldExe := updateExecutablePath
	t.Cleanup(func() {
		restartState, restartDelay = oldState, oldDelay
		restartValidateFn, restartShutdownFn, restartInPlaceFn = oldValidate, oldShutdown, oldExec
		updateExecutablePath = oldExe
	})

	restartState = &restartTracker{}
	restartDelay = 0
	updateExecutablePath = func() (string, error) { return "/tmp/fake-crproxy", nil }

	drained, execd := false, false
	restartValidateFn = func(path string) error { return errors.New("bad CPU type in executable") }
	restartShutdownFn = func(ctx context.Context) error { drained = true; return nil }
	restartInPlaceFn = func(exe string, args []string) error { execd = true; return nil }

	if !restartState.begin() {
		t.Fatal("准备失败")
	}
	performRestart()

	if execd {
		t.Error("预检失败后不应该 exec")
	}
	if drained {
		t.Error("预检失败后不应该关闭 HTTP 服务")
	}
	requested, errMsg := restartState.snapshot()
	if requested {
		t.Error("失败后应允许重新发起重启")
	}
	if !strings.Contains(errMsg, "bad CPU type") {
		t.Errorf("失败原因未记录: %q", errMsg)
	}
}

// 正常路径：先优雅关闭（drain），再原地 exec，且 argv[0] 指向二进制路径
func TestPerformRestartDrainsThenExecs(t *testing.T) {
	oldState, oldDelay := restartState, restartDelay
	oldValidate, oldShutdown, oldExec := restartValidateFn, restartShutdownFn, restartInPlaceFn
	oldExe := updateExecutablePath
	t.Cleanup(func() {
		restartState, restartDelay = oldState, oldDelay
		restartValidateFn, restartShutdownFn, restartInPlaceFn = oldValidate, oldShutdown, oldExec
		updateExecutablePath = oldExe
	})

	restartState = &restartTracker{}
	restartDelay = 0
	const exe = "/opt/crproxy/crproxy"
	updateExecutablePath = func() (string, error) { return exe, nil }

	var order []string
	restartValidateFn = func(path string) error { order = append(order, "validate:"+path); return nil }
	restartShutdownFn = func(ctx context.Context) error {
		order = append(order, "drain")
		// 关闭必须带上超时，否则等待在途请求可能无限期
		if _, ok := ctx.Deadline(); !ok {
			t.Error("drain context 应带超时")
		}
		return nil
	}
	var gotExe string
	var gotArgs []string
	restartInPlaceFn = func(exePath string, args []string) error {
		order = append(order, "exec")
		gotExe, gotArgs = exePath, args
		return nil
	}

	if !restartState.begin() {
		t.Fatal("准备失败")
	}
	performRestart()

	want := []string{"validate:" + exe, "drain", "exec"}
	if len(order) != len(want) {
		t.Fatalf("调用顺序 = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("调用顺序 = %v, want %v", order, want)
		}
	}
	if gotExe != exe {
		t.Errorf("exec 路径 = %q, want %q", gotExe, exe)
	}
	if len(gotArgs) == 0 || gotArgs[0] != os.Args[0] {
		t.Errorf("argv 应以原参数启动，got %v", gotArgs)
	}
}

// 预检真的会去跑 -version：不存在的文件必须报错（这条覆盖真实实现对二进制的要求）
func TestValidateRestartBinaryRejectsMissingFile(t *testing.T) {
	err := validateRestartBinary("/nonexistent/crproxy-" + time.Now().Format("150405"))
	if err == nil {
		t.Fatal("对一个不存在的文件应当预检失败")
	}
}
