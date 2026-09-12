//go:build !lite
// +build !lite

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ============================ 运行环境探测 ============================
//
// 重启本身在所有 Unix 环境下用同一套机制（原地 exec，见 restart_unix.go），
// 探测的目的不是"换一种重启方式"，而是：
//   1. 告诉使用者当前部署形态，以及重启后会发生什么（尤其是容器里更新二进制会白做）；
//   2. 决定能力边界（Windows 不支持原地重启）。

// 部署形态
const (
	envKubernetes = "kubernetes"
	envDocker     = "docker"
	envSystemd    = "systemd"
	envLaunchd    = "launchd"
	envSupervisor = "supervisor"
	envStandalone = "standalone"
)

// restartEnvironment 当前进程的部署形态。
type restartEnvironment struct {
	Kind        string `json:"kind"`
	InContainer bool   `json:"inContainer"`
	ServiceName string `json:"serviceName,omitempty"`
}

// 可注入点（便于测试）
var (
	restartGetenv     = os.Getenv
	restartFileExists = func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}
	restartPID = os.Getpid
	// restartPPID 用于区分"真的被 init 托管"和"环境变量恰好带着"：
	// 被 systemd/launchd 托管的进程父进程是 1，终端里手动起的不是。
	restartPPID = os.Getppid
	// 用启动时记录的二进制路径做原地重启（同一语义，测试同样可注入）。
	// 不能用 os.Executable()：更新替换后 /proc/self/exe 跟随 rename 指向
	// *.backup（旧版本），用它 exec 会把旧版本重新拉起来。
	restartExecutablePath = startupExecutablePath
)

// detectRestartEnvironment 判断当前的部署形态。
func detectRestartEnvironment() restartEnvironment {
	env := restartEnvironment{Kind: envStandalone}
	ppid := restartPPID()

	// 容器优先：容器语义比宿主机的 init 系统更重要
	switch {
	case restartGetenv("KUBERNETES_SERVICE_HOST") != "":
		env.Kind = envKubernetes
		env.InContainer = true
		if ns := restartGetenv("POD_NAMESPACE"); ns != "" {
			env.ServiceName = ns
		}
	case restartFileExists("/.dockerenv"), restartFileExists("/run/.containerenv"):
		env.Kind = envDocker
		env.InContainer = true
	case restartGetenv("container") != "":
		env.Kind = envDocker
		env.InContainer = true
	case restartGetenv("INVOCATION_ID") != "":
		// systemd 为每个 unit 进程注入，交互式 shell 不会继承
		env.Kind = envSystemd
	case (restartGetenv("XPC_SERVICE_NAME") != "" || restartGetenv("LAUNCH_JOBKEY_LABEL") != "") && ppid == 1:
		// XPC_SERVICE_NAME 在 macOS 图形会话里是"环境自带"的，
		// 终端里手动启动的服务也会有，所以必须再加"父进程是 1"
		env.Kind = envLaunchd
	case restartFileExists("/run/systemd/system") && ppid == 1:
		env.Kind = envSystemd
	case restartGetenv("SUPERVISOR_ENABLED") != "":
		// supervisor 的子进程父进程是 supervisord（不是 1），只能用环境变量判断
		env.Kind = envSupervisor
	}
	return env
}

// ============================ 重启状态 ============================

// restartTracker 记录重启请求，避免重复触发。
// 注意：重启成功后本进程被 exec 替换，所以不存在"完成"状态可供查询，
// 前端通过轮询 /healthz 判断服务是否已经回来。
type restartTracker struct {
	mu        sync.Mutex
	requested bool
	errMsg    string
	// 等待在途下载结束期间的状态（供 /admin/api/restart/info 展示）。
	// 只有这个阶段可以取消；一旦进入优雅关闭/exec，取消一律拒绝。
	waiting    bool
	waitStart  time.Time
	waitActive int
	cancelReq  bool
}

var restartState = &restartTracker{}

func (r *restartTracker) begin() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.requested {
		return false
	}
	r.requested = true
	r.errMsg = ""
	return true
}

func (r *restartTracker) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requested = false
	if err != nil {
		r.errMsg = err.Error()
	}
}

func (r *restartTracker) snapshot() (requested bool, errMsg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requested, r.errMsg
}

// beginWait 进入「等待在途下载结束」阶段。
func (r *restartTracker) beginWait(active int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waiting = true
	r.waitStart = time.Now()
	r.waitActive = active
	r.cancelReq = false
}

// updateWait 刷新等待期间仍在进行的下载数。
func (r *restartTracker) updateWait(active int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waitActive = active
}

// requestCancel 在等待阶段登记一次取消请求。
// 返回 false 表示当前没有可取消的等待（不在等待中，或已进入关闭/exec 阶段）。
func (r *restartTracker) requestCancel() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.waiting {
		return false
	}
	r.cancelReq = true
	return true
}

// waitCanceled 读取等待期间是否收到过取消请求（等待循环轮询用）。
func (r *restartTracker) waitCanceled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancelReq
}

// finishWait 结束等待阶段，返回期间是否收到过取消请求。
// 与 requestCancel 共用同一把锁完成「等待中 → 不可取消」的原子切换：
// 一旦返回（无论是否取消），后续的取消请求都会被拒绝。
func (r *restartTracker) finishWait() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	canceled := r.cancelReq
	r.cancelReq = false
	r.waiting = false
	r.waitActive = 0
	return canceled
}

// waitSnapshot 读取等待阶段状态。
func (r *restartTracker) waitSnapshot() (waiting bool, start time.Time, active int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.waiting, r.waitStart, r.waitActive
}

// ============================ 重启流程 ============================

// 可注入的钩子（由 main.go / 测试替换）
var (
	// restartDelay 响应返回与真正重启之间的间隔（测试里可缩短）
	restartDelay = restartResponseDelay
	// restartInPlaceFn 实际执行 exec 的实现（按平台提供，测试可替换）
	restartInPlaceFn = restartInPlaceOS
	// restartShutdownFn 重启前优雅关闭：保存统计 + 关闭 HTTP 监听并等待在途请求
	restartShutdownFn = func(ctx context.Context) error { return nil }
	// restartValidateFn 重启前预检：确认新二进制能正常执行
	restartValidateFn = validateRestartBinary
	// restartActiveDownloadsFn 统计当前在途的下载任务数（测试可替换）
	restartActiveDownloadsFn = func() int { return live.ActiveDownloads() }
	// restartQuietPeriod 下载全部结束后的静默期：连续这么久没有下载才重启
	restartQuietPeriod = 30 * time.Second
	// restartWaitPollInterval 等待期间轮询在途下载数的间隔
	restartWaitPollInterval = time.Second
)

const (
	// restartResponseDelay 先让 HTTP 响应回给浏览器，再动手重启
	restartResponseDelay = 600 * time.Millisecond
	// restartDrainTimeout 优雅关闭时等待在途请求的上限
	restartDrainTimeout = 5 * time.Second
	// restartValidateTimeout 预检新二进制的超时
	restartValidateTimeout = 5 * time.Second
)

// restartInfoView 是 /admin/api/restart/info 的响应
type restartInfoView struct {
	Supported      bool               `json:"supported"`
	Method         string             `json:"method"`
	Environment    restartEnvironment `json:"environment"`
	PID            int                `json:"pid"`
	StartedAt      int64              `json:"startedAt"`
	Uptime         float64            `json:"uptime"`
	Version        string             `json:"version"`
	RestartPending bool               `json:"restartPending"`
	UpdateRunning  bool               `json:"updateRunning"`
	Restarting     bool               `json:"restarting"`
	ValidateHint   string             `json:"validateHint,omitempty"`
	// 在途下载与重启前等待状态（等待中才有 waitElapsed）
	ActiveDownloads  int     `json:"activeDownloads"`
	WaitingDownloads bool    `json:"waitingDownloads"`
	WaitElapsed      float64 `json:"waitElapsed,omitempty"`
}

// processStartAt 记录本进程的启动时间（供 uptime 展示与重启验证）
var processStartAt = time.Now()

func restartInfo() restartInfoView {
	requested, _ := restartState.snapshot()
	pending, err := isRestartPending()
	if err != nil {
		pending = false
	}
	progress := updateProgress.snapshot()

	view := restartInfoView{
		Supported:       restartSupported,
		Method:          restartMethodName,
		Environment:     detectRestartEnvironment(),
		PID:             restartPID(),
		StartedAt:       processStartAt.UnixMilli(),
		Uptime:          time.Since(processStartAt).Seconds(),
		Version:         version,
		RestartPending:  pending,
		UpdateRunning:   progress.Running,
		Restarting:      requested,
		ActiveDownloads: restartActiveDownloadsFn(),
	}
	if waiting, start, _ := restartState.waitSnapshot(); waiting {
		view.WaitingDownloads = true
		view.WaitElapsed = time.Since(start).Seconds()
	}
	return view
}

// validateRestartBinary 跑一次新二进制的 -version，确认它真的能执行。
// 这能在原地 exec 之前拦住"下载了错误架构/损坏文件"的情况——
// 否则 exec 失败后服务就再也起不来了。
func validateRestartBinary(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), restartValidateTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, "-version").CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		return fmt.Errorf("new binary failed to run (%v): %s", err, output)
	}
	if !strings.Contains(output, "version:") {
		return fmt.Errorf("unexpected output from new binary: %q", output)
	}
	return nil
}

// requestRestart 登记一次重启。返回 false 表示已经在重启中。
func requestRestart() bool {
	if !restartSupported {
		return false
	}
	if progress := updateProgress.snapshot(); progress.Running {
		return false
	}
	return restartState.begin()
}

// performRestart 延迟一小段时间（让 /restart 的响应先回到浏览器），
// 然后等待在途下载结束、优雅关闭 HTTP 服务并原地 exec 新二进制。
func performRestart() {
	time.Sleep(restartDelay)

	exe, err := restartExecutablePath()
	if err != nil {
		restartState.fail(fmt.Errorf("cannot locate executable: %w", err))
		slog.Error("restart aborted: cannot locate executable", "error", err)
		return
	}

	// 预检：新二进制跑不起来就不重启，保持当前服务存活。
	// 放在等待下载之前——预检失败应立刻放弃，不该让用户白等几十秒。
	if err := restartValidateFn(exe); err != nil {
		restartState.fail(err)
		slog.Error("restart aborted: new binary failed pre-flight check", "error", err, "path", exe)
		return
	}

	// 等待在途下载结束（结束后再静默一段时间），期间不关闭 HTTP 服务。
	// 等待阶段可随时通过 /admin/api/restart/cancel 取消整次重启。
	if !waitForDownloadsQuiet() {
		slog.Info("restart canceled while waiting, service keeps running", "pid", restartPID())
		return
	}

	// 优雅关闭：先保存统计，再停止接收新请求并等待在途请求结束
	ctx, cancel := context.WithTimeout(context.Background(), restartDrainTimeout)
	defer cancel()
	if err := restartShutdownFn(ctx); err != nil {
		slog.Warn("graceful shutdown before restart failed", "error", err)
	}

	// 注意：这里不再改动 restartState —— 状态保持 requested，
	// 这样重启窗口内的重复请求会被拒绝。
	slog.Info("restarting in place", "path", exe, "pid", restartPID(), "args", os.Args)

	// exec 成功不会返回；PID 保持不变，因此 systemd/容器都视为同一次启动
	// （见 restart_unix.go / restart_windows.go）
	if err := restartInPlaceFn(exe, os.Args); err != nil {
		slog.Error("in-place restart failed, exiting", "error", err)
		os.Exit(1)
	}
}

// waitForDownloadsQuiet 等待在途下载结束，再留一段静默期后才放行重启。
//
//   - 请求重启的瞬间没有任何下载 → 立即放行，不人为拖慢正常重启；
//   - 有下载在跑 → 等它们结束，且连续 restartQuietPeriod 秒没有任何下载
//     才放行（给「上一层拉完、马上开始下一层」的连续拉取留缓冲，
//     静默期内出现新下载则重新计时）；
//   - 不设等待上限：宁可重启慢，也不打断客户端的下载。等待期间 HTTP
//     服务照常工作，/restart/info 会通过 waitingDownloads /
//     activeDownloads / waitElapsed 反映进度；每分钟记一条进度日志，
//     避免长等待时看起来像卡死；
//   - 等待期间收到取消请求（/admin/api/restart/cancel）→ 放弃本次重启，
//     返回 false，服务继续正常运行，之后可以重新发起重启。
//
// 返回 true 表示可以继续重启流程，false 表示已被取消。
func waitForDownloadsQuiet() bool {
	initial := restartActiveDownloadsFn()
	if initial == 0 {
		return true
	}

	restartState.beginWait(initial)
	slog.Info("waiting for active downloads before restart",
		"downloads", initial, "quiet_period", restartQuietPeriod)

	start := time.Now()
	lastBusy := start
	lastLogged := start
	for {
		time.Sleep(restartWaitPollInterval)

		if restartState.waitCanceled() {
			break
		}

		active := restartActiveDownloadsFn()
		now := time.Now()
		if active > 0 {
			lastBusy = now
		}
		restartState.updateWait(active)

		if now.Sub(lastBusy) >= restartQuietPeriod {
			break
		}
		if now.Sub(lastLogged) >= time.Minute {
			lastLogged = now
			slog.Info("still waiting for active downloads before restart",
				"active", active, "waited", now.Sub(start).Round(time.Second))
		}
	}

	if canceled := restartState.finishWait(); canceled {
		// 复位 requested，允许之后重新发起重启
		restartState.fail(nil)
		slog.Info("restart canceled during download wait",
			"waited", time.Since(start).Round(time.Second))
		return false
	}

	slog.Info("download wait finished, proceeding with restart",
		"waited", time.Since(start).Round(time.Second))
	return true
}
