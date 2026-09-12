//go:build !lite
// +build !lite

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const testOldBinary = "OLD BINARY CONTENT"

// testAssetName 与 performUpdate 里拼出来的产物名保持一致
func testAssetName() string {
	name := fmt.Sprintf("crproxy-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// testBinaryPayload 造一个带正确魔数、体积超过下限的假二进制
func testBinaryPayload(size int) []byte {
	var head []byte
	switch runtime.GOOS {
	case "darwin":
		head = []byte{0xcf, 0xfa, 0xed, 0xfe} // Mach-O 64 位小端
	case "windows":
		head = []byte{'M', 'Z', 0x90, 0x00}
	default:
		head = []byte{0x7f, 'E', 'L', 'F'}
	}
	buf := make([]byte, size)
	copy(buf, head)
	for i := 4; i < size; i++ {
		buf[i] = byte(i % 251)
	}
	return buf
}

// setupFakeUpdater 把更新器指向临时"可执行文件"和一个假的 GitHub API。
// serveAsset 负责 /dl 的响应体，返回 false 表示测试自己处理了响应。
func setupFakeUpdater(t *testing.T, serveAsset func(w http.ResponseWriter, r *http.Request)) (target string, server *httptest.Server) {
	t.Helper()

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/fimreal/crproxy/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v9.9.9",
			"assets": []map[string]string{
				{"name": testAssetName(), "browser_download_url": srv.URL + "/dl"},
			},
		})
	})
	mux.HandleFunc("/dl", serveAsset)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	oldAPI := updateAPIBase
	updateAPIBase = srv.URL
	t.Cleanup(func() { updateAPIBase = oldAPI })

	dir := t.TempDir()
	target = filepath.Join(dir, "crproxy-test")
	if err := os.WriteFile(target, []byte(testOldBinary), 0755); err != nil {
		t.Fatalf("准备旧二进制失败: %v", err)
	}

	oldExec := updateExecutablePath
	updateExecutablePath = func() (string, error) { return target, nil }
	t.Cleanup(func() { updateExecutablePath = oldExec })

	return target, srv
}

// 更新替换用 rename 把运行中的二进制改名成 *.backup 后，Linux 上 os.Executable()
// （/proc/self/exe）会跟随 inode 返回 .backup 的路径。安装目标与重启路径必须仍然
// 使用启动时记录的原始路径，否则会"更新成功、重启跑回旧版本"（v0.5.11 修复的 bug）。
func TestStartupExecutablePathPrefersRecordedPath(t *testing.T) {
	oldPath, oldExec := initialBinaryPath, updateExecutablePath
	t.Cleanup(func() { initialBinaryPath, updateExecutablePath = oldPath, oldExec })

	dir := t.TempDir()
	recorded := filepath.Join(dir, "crproxy")
	// 模拟 Linux：/proc/self/exe 在 rename 之后指向 .backup（旧版本的当前位置）
	renamed := filepath.Join(dir, "crproxy.backup")
	initialBinaryPath = recorded
	updateExecutablePath = func() (string, error) { return renamed, nil }

	got, err := startupExecutablePath()
	if err != nil {
		t.Fatalf("startupExecutablePath 失败: %v", err)
	}
	if got != recorded {
		t.Errorf("startupExecutablePath() = %q, want 启动时记录的 %q（重定向到旧版本路径）", got, recorded)
	}
}

// initialBinaryPath 未记录时（防御性场景）应回退到 os.Executable
func TestStartupExecutablePathFallsBackToExecutable(t *testing.T) {
	oldPath, oldExec := initialBinaryPath, updateExecutablePath
	t.Cleanup(func() { initialBinaryPath, updateExecutablePath = oldPath, oldExec })

	dir := t.TempDir()
	fallback := filepath.Join(dir, "fallback-crproxy")
	initialBinaryPath = ""
	updateExecutablePath = func() (string, error) { return fallback, nil }

	got, err := startupExecutablePath()
	if err != nil {
		t.Fatalf("startupExecutablePath 失败: %v", err)
	}
	if got != fallback {
		t.Errorf("startupExecutablePath() = %q, want %q", got, fallback)
	}
}

// 同一进程内连续两次更新：备份是滚动单份，不应累积出多个 .backup/.new 文件。
func TestPerformUpdateKeepsSingleRollingBackup(t *testing.T) {
	payload := testBinaryPayload(int(updateMinBinarySize) + 4096)
	target, _ := setupFakeUpdater(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.WriteHeader(http.StatusOK)
		w.Write(payload)
	})

	for round := 1; round <= 2; round++ {
		if _, err := performUpdate(); err != nil {
			t.Fatalf("第 %d 次 performUpdate 失败: %v", round, err)
		}
	}

	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{filepath.Base(target), filepath.Base(target) + ".backup"}
	if len(names) != len(want) {
		t.Errorf("连续两次更新后目录应有 %d 个文件, got %d 个: %v（备份在累积）", len(want), len(names), names)
	}
	sort.Strings(names)
	wantSorted := append([]string(nil), want...)
	sort.Strings(wantSorted)
	for i := range wantSorted {
		if i >= len(names) || names[i] != wantSorted[i] {
			t.Errorf("目录内容 = %v, want %v", names, wantSorted)
			break
		}
	}
}

// 正常流程：下载 → 校验 → 备份 → 替换，并且全程进度可查。
func TestPerformUpdateReplacesBinaryAndReportsProgress(t *testing.T) {
	payload := testBinaryPayload(int(updateMinBinarySize) + 4096)
	target, _ := setupFakeUpdater(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.WriteHeader(http.StatusOK)
		// 分几块写并放慢，模拟流式下载（太快的传输不计算速率）
		for off := 0; off < len(payload); off += 256 * 1024 {
			end := off + 256*1024
			if end > len(payload) {
				end = len(payload)
			}
			w.Write(payload[off:end])
			w.(http.Flusher).Flush()
			time.Sleep(60 * time.Millisecond)
		}
	})

	newVersion, err := performUpdate()
	if err != nil {
		t.Fatalf("performUpdate 失败: %v", err)
	}
	if newVersion != "v9.9.9" {
		t.Errorf("newVersion = %q, want v9.9.9", newVersion)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("读取替换后的文件失败: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("替换后的文件内容不符（got %d 字节, want %d）", len(got), len(payload))
	}

	backup, err := os.ReadFile(target + ".backup")
	if err != nil {
		t.Fatalf("备份文件不存在: %v", err)
	}
	if string(backup) != testOldBinary {
		t.Errorf("备份内容 = %q, want %q", backup, testOldBinary)
	}

	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(target), "*.new")); len(leftovers) != 0 {
		t.Errorf("临时文件未清理: %v", leftovers)
	}

	p := updateProgress.snapshot()
	if p.Stage != string(updateStageDone) || p.Running {
		t.Errorf("进度状态 = %q running=%v, want done/false", p.Stage, p.Running)
	}
	if p.Version != "v9.9.9" {
		t.Errorf("进度里的版本 = %q, want v9.9.9", p.Version)
	}
	if p.Downloaded != int64(len(payload)) || p.Percent != 100 {
		t.Errorf("进度字节 = %d (%.1f%%), want %d (100%%)", p.Downloaded, p.Percent, len(payload))
	}
	if p.Speed <= 0 {
		t.Errorf("下载速率 = %v, want > 0", p.Speed)
	}
}

// 下载到的不是可执行文件（例如 CDN 返回 200 的 HTML 错误页）时必须拒绝替换。
func TestPerformUpdateRejectsNonExecutablePayload(t *testing.T) {
	html := append([]byte("<html><body>not found</body></html>"), bytes.Repeat([]byte(" "), int(updateMinBinarySize))...)
	target, _ := setupFakeUpdater(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(html)))
		w.WriteHeader(http.StatusOK)
		w.Write(html)
	})

	_, err := performUpdate()
	if err == nil {
		t.Fatal("期望拒绝非可执行文件，却成功了")
	}
	if !strings.Contains(err.Error(), "not a valid") {
		t.Errorf("错误信息未说明文件格式问题: %v", err)
	}

	got, _ := os.ReadFile(target)
	if string(got) != testOldBinary {
		t.Error("原二进制被改动了")
	}
	if _, err := os.Stat(target + ".backup"); err == nil {
		t.Error("不应产生备份文件")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(target), "*.new")); len(leftovers) != 0 {
		t.Errorf("失败后临时文件未清理: %v", leftovers)
	}

	p := updateProgress.snapshot()
	if p.Stage != string(updateStageFailed) || p.Error == "" || p.Running {
		t.Errorf("失败状态未记录: stage=%q error=%q running=%v", p.Stage, p.Error, p.Running)
	}
}

// 下载被截断（长度对不上）时必须失败，且不动原文件。
func TestPerformUpdateFailsOnTruncatedDownload(t *testing.T) {
	payload := testBinaryPayload(int(updateMinBinarySize) + 4096)
	target, _ := setupFakeUpdater(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.WriteHeader(http.StatusOK)
		w.Write(payload[:len(payload)/2]) // 只写一半
	})

	if _, err := performUpdate(); err == nil {
		t.Fatal("期望截断下载失败，却成功了")
	}

	got, _ := os.ReadFile(target)
	if string(got) != testOldBinary {
		t.Error("失败后原二进制被改动了")
	}
	if p := updateProgress.snapshot(); p.Stage != string(updateStageFailed) || p.Running {
		t.Errorf("失败状态未记录: stage=%q running=%v", p.Stage, p.Running)
	}
}

// 并发触发时只能有一个更新真正执行，另一个必须明确被拒绝。
func TestPerformUpdateRejectsConcurrentRuns(t *testing.T) {
	payload := testBinaryPayload(int(updateMinBinarySize) + 4096)
	target, _ := setupFakeUpdater(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.WriteHeader(http.StatusOK)
		for off := 0; off < len(payload); off += 256 * 1024 {
			end := off + 256*1024
			if end > len(payload) {
				end = len(payload)
			}
			w.Write(payload[off:end])
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
	})

	var wg sync.WaitGroup
	errs := make([]error, 2)
	versions := make([]string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			versions[i], errs[i] = performUpdate()
		}(i)
	}
	wg.Wait()

	var okCount, busyCount int
	for i, err := range errs {
		switch {
		case err == nil:
			okCount++
			if versions[i] != "v9.9.9" {
				t.Errorf("成功那次返回的版本 = %q", versions[i])
			}
		case errors.Is(err, ErrUpdateInProgress):
			busyCount++
		default:
			t.Errorf("并发调用出现意外错误: %v", err)
		}
	}
	if okCount != 1 || busyCount != 1 {
		t.Errorf("并发结果 = 成功 %d 次 / 拒绝 %d 次, want 各 1 次", okCount, busyCount)
	}

	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, payload) {
		t.Error("并发下载后目标文件内容不对")
	}
}

// 状态机本身：同一时刻只能有一个 running，失败原因要保留。
func TestUpdateTrackerStateMachine(t *testing.T) {
	tracker := &updateTracker{stage: updateStageIdle}

	if got := tracker.snapshot(); got.Stage != string(updateStageIdle) || got.Running {
		t.Fatalf("初始状态 = %q running=%v, want idle/false", got.Stage, got.Running)
	}
	if !tracker.begin() {
		t.Fatal("第一次 begin 应成功")
	}
	if tracker.begin() {
		t.Fatal("已有任务在执行时 begin 应失败")
	}
	tracker.beginDownload("v1.2.3", 1000)
	tracker.addBytes(250)
	mid := tracker.snapshot()
	if mid.Stage != string(updateStageDownloading) || mid.Percent != 25 || mid.Version != "v1.2.3" {
		t.Errorf("下载中状态 = stage=%q percent=%v version=%q", mid.Stage, mid.Percent, mid.Version)
	}

	tracker.fail(errors.New("disk full"))
	done := tracker.snapshot()
	if done.Running || done.Stage != string(updateStageFailed) || done.Error != "disk full" {
		t.Errorf("失败状态 = running=%v stage=%q error=%q", done.Running, done.Stage, done.Error)
	}
	if !tracker.begin() {
		t.Error("失败后应能重新开始")
	}
	tracker.complete("v1.2.3")
	final := tracker.snapshot()
	if final.Stage != string(updateStageDone) || final.Error != "" || final.Running {
		t.Errorf("完成状态 = stage=%q error=%q running=%v", final.Stage, final.Error, final.Running)
	}
}
