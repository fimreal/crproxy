//go:build !lite
// +build !lite

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// 用于检测是否需要重启
var (
	initialBinaryModTime time.Time
	initialBinaryPath    string
)

// 更新的可注入参数：生产使用默认值，测试里替换成 httptest 服务与临时文件。
var (
	updateExecutablePath  = os.Executable
	updateAPIBase         = "https://api.github.com"
	updateRepo            = "fimreal/crproxy"
	updateAPITimeout      = 10 * time.Second
	updateDownloadTimeout = 5 * time.Minute
	// updateMinBinarySize 下载结果的最小体积，低于此值一律视为异常响应
	updateMinBinarySize = int64(1 << 20)
)

// ErrUpdateInProgress 表示已有更新任务在执行。
var ErrUpdateInProgress = errors.New("an update is already in progress")

// GitHubRelease GitHub release 信息
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// UpdateInfo 更新信息
type UpdateInfo struct {
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	HasUpdate      bool   `json:"hasUpdate"`
}

// checkForUpdate 检查是否有更新
func checkForUpdate() (*UpdateInfo, error) {
	apiURL := fmt.Sprintf("%s/repos/%s/releases/latest", updateAPIBase, updateRepo)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", updateUserAgent())

	client := &http.Client{Timeout: updateAPITimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release info: %w", err)
	}

	info := &UpdateInfo{
		CurrentVersion: version,
		LatestVersion:  release.TagName,
		HasUpdate:      release.TagName != version,
	}
	return info, nil
}

// ============================ 进度上报 ============================
//
// 一次更新要经历「检查 → 下载(数分钟) → 校验 → 备份 → 替换」，
// 而 /admin/api/update 这个请求要等全部结束才返回，中间没有任何信息。
// 所以把状态放进进程级 tracker，由前端轮询 /admin/api/update/progress 读取。

// updateStage 更新所处的阶段
type updateStage string

const (
	updateStageIdle        updateStage = "idle"
	updateStageChecking    updateStage = "checking"
	updateStageDownloading updateStage = "downloading"
	updateStageVerifying   updateStage = "verifying"
	updateStageBackingUp   updateStage = "backing_up"
	updateStageReplacing   updateStage = "replacing"
	updateStageDone        updateStage = "done"
	updateStageFailed      updateStage = "failed"
)

// updateProgressView 是对外的只读进度视图
type updateProgressView struct {
	Stage       string  `json:"stage"`
	Running     bool    `json:"running"`
	Version     string  `json:"version,omitempty"`
	Downloaded  int64   `json:"downloaded"`
	Total       int64   `json:"total"`
	Percent     float64 `json:"percent"`
	Speed       float64 `json:"speed"`
	Elapsed     float64 `json:"elapsed"`
	Error       string  `json:"error,omitempty"`
	CompletedAt int64   `json:"completedAt,omitempty"`
}

type updateTracker struct {
	mu          sync.Mutex
	running     bool
	stage       updateStage
	version     string
	downloaded  int64
	total       int64
	startedAt   time.Time
	dlStartedAt time.Time
	errMsg      string
	completedAt time.Time
}

var updateProgress = &updateTracker{stage: updateStageIdle}

// begin 尝试开始一次更新；已有任务在执行时返回 false。
func (u *updateTracker) begin() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.running {
		return false
	}
	u.running = true
	u.stage = updateStageChecking
	u.version = ""
	u.downloaded = 0
	u.total = 0
	u.startedAt = time.Now()
	u.dlStartedAt = time.Time{}
	u.errMsg = ""
	u.completedAt = time.Time{}
	return true
}

func (u *updateTracker) setStage(stage updateStage) {
	u.mu.Lock()
	u.stage = stage
	u.mu.Unlock()
}

// beginDownload 记录目标版本与总长度，开始累计下载进度。
func (u *updateTracker) beginDownload(version string, total int64) {
	u.mu.Lock()
	u.stage = updateStageDownloading
	u.version = version
	u.total = total
	u.downloaded = 0
	u.dlStartedAt = time.Now()
	u.mu.Unlock()
}

func (u *updateTracker) addBytes(n int64) {
	if n <= 0 {
		return
	}
	u.mu.Lock()
	u.downloaded += n
	u.mu.Unlock()
}

// fail 结束本次更新并记录失败原因。
func (u *updateTracker) fail(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.running = false
	u.stage = updateStageFailed
	if err != nil {
		u.errMsg = err.Error()
	}
	u.completedAt = time.Now()
}

// complete 结束本次更新并记录成功。
func (u *updateTracker) complete(version string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.running = false
	u.stage = updateStageDone
	if version != "" {
		u.version = version
	}
	u.errMsg = ""
	u.completedAt = time.Now()
}

func (u *updateTracker) snapshot() updateProgressView {
	u.mu.Lock()
	defer u.mu.Unlock()

	view := updateProgressView{
		Stage:      string(u.stage),
		Running:    u.running,
		Version:    u.version,
		Downloaded: u.downloaded,
		Total:      u.total,
		Error:      u.errMsg,
	}
	if u.total > 0 {
		view.Percent = float64(u.downloaded) / float64(u.total) * 100
		if view.Percent > 100 {
			view.Percent = 100
		}
	}
	if !u.startedAt.IsZero() {
		end := time.Now()
		if !u.running && !u.completedAt.IsZero() {
			end = u.completedAt
		}
		view.Elapsed = end.Sub(u.startedAt).Seconds()
	}
	if !u.dlStartedAt.IsZero() {
		span := time.Since(u.dlStartedAt).Seconds()
		if !u.running && !u.completedAt.IsZero() {
			span = u.completedAt.Sub(u.dlStartedAt).Seconds()
		}
		if span > 0.2 {
			view.Speed = float64(u.downloaded) / span
		}
	}
	if !u.completedAt.IsZero() {
		view.CompletedAt = u.completedAt.UnixMilli()
	}
	return view
}

// copyWithProgress 分块拷贝并实时累计进度，避免整段下载期间完全没有状态。
func copyWithProgress(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return written, werr
			}
			written += int64(n)
			updateProgress.addBytes(int64(n))
		}
		if err == io.EOF {
			return written, nil
		}
		if err != nil {
			return written, err
		}
	}
}

// validateBinaryPayload 校验下载到的文件确实是对应平台的可执行文件，
// 否则一旦 CDN 返回 HTTP 200 的错误页，就会被当成新版本装上去。
func validateBinaryPayload(path, goos string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat downloaded file: %w", err)
	}
	if info.Size() < updateMinBinarySize {
		return fmt.Errorf("downloaded file is too small (%d bytes), refusing to install", info.Size())
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open downloaded file: %w", err)
	}
	defer f.Close()

	head := make([]byte, 4)
	if _, err := io.ReadFull(f, head); err != nil {
		return fmt.Errorf("failed to read downloaded file header: %w", err)
	}

	switch goos {
	case "linux":
		if string(head) != "\x7fELF" {
			return errBadBinaryFormat("ELF")
		}
	case "darwin":
		// Mach-O 32/64 位、大小端与通用二进制（fat）几种魔数
		ok := (head[0] == 0xfe && head[1] == 0xed && head[2] == 0xfa && (head[3] == 0xce || head[3] == 0xcf)) ||
			(head[0] == 0xce && head[1] == 0xfa && head[2] == 0xed && head[3] == 0xfe) ||
			(head[0] == 0xcf && head[1] == 0xfa && head[2] == 0xed && head[3] == 0xfe) ||
			string(head) == "\xca\xfe\xba\xbe"
		if !ok {
			return errBadBinaryFormat("Mach-O")
		}
	case "windows":
		if head[0] != 'M' || head[1] != 'Z' {
			return errBadBinaryFormat("PE")
		}
	}
	return nil
}

func errBadBinaryFormat(want string) error {
	return fmt.Errorf("downloaded file is not a valid %s executable (unexpected header), refusing to install", want)
}

func updateUserAgent() string {
	return fmt.Sprintf("crproxy/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
}

// recordStartupBinaryInfo 记录启动时的二进制文件信息
func recordStartupBinaryInfo() error {
	execPath, err := updateExecutablePath()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	initialBinaryPath = execPath

	info, err := os.Stat(execPath)
	if err != nil {
		return fmt.Errorf("failed to stat executable: %w", err)
	}
	initialBinaryModTime = info.ModTime()

	slog.Info("recorded startup binary info", "path", execPath, "modTime", initialBinaryModTime)
	return nil
}

// isRestartPending 检查二进制文件是否被更新，需要重启
func isRestartPending() (bool, error) {
	// 如果没有记录初始信息，说明没有更新过
	if initialBinaryPath == "" {
		return false, nil
	}

	execPath, err := updateExecutablePath()
	if err != nil {
		return false, fmt.Errorf("failed to get executable path: %w", err)
	}

	info, err := os.Stat(execPath)
	if err != nil {
		return false, fmt.Errorf("failed to stat executable: %w", err)
	}

	// 如果二进制文件的修改时间变了，说明文件被替换了
	if !info.ModTime().Equal(initialBinaryModTime) {
		slog.Info("binary modified after startup, restart required",
			"original", initialBinaryModTime,
			"current", info.ModTime())
		return true, nil
	}

	return false, nil
}

// checkWritePermission 检查是否有写入权限
func checkWritePermission(execPath string) error {
	// 检查文件所在目录是否可写
	execDir := filepath.Dir(execPath)

	// 尝试在目标目录创建临时文件来测试写入权限
	testFile := filepath.Join(execDir, ".write_test")
	f, err := os.Create(testFile)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("no write permission to %s (permission denied)", execDir)
		}
		return fmt.Errorf("cannot write to %s: %w", execDir, err)
	}
	f.Close()
	os.Remove(testFile)

	// 注意：在 Linux 上，只要目录可写，就可以通过 rename 替换运行中的二进制文件
	// 不需要检查二进制文件本身的写权限

	return nil
}

// performUpdate 执行更新。整个过程的状态会写入 updateProgress，供前端轮询。
func performUpdate() (newVersion string, err error) {
	execPath, err := updateExecutablePath()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	// 同一时刻只允许一个更新任务，否则并发下载会互相覆盖备份
	if !updateProgress.begin() {
		return "", ErrUpdateInProgress
	}

	var (
		newFile   string
		installed bool
	)
	defer func() {
		if err != nil {
			if newFile != "" && !installed {
				os.Remove(newFile)
			}
			updateProgress.fail(err)
			return
		}
		updateProgress.complete(newVersion)
	}()

	execDir := filepath.Dir(execPath)
	slog.Info("checking for updates", "current_version", version, "executable", execPath)

	// 先检查写入权限（避免无意义的下载）
	if err := checkWritePermission(execPath); err != nil {
		return "", fmt.Errorf("no write permission for in-place update: %w\n\nPlease update manually:\n  1. Visit: https://github.com/%s/releases/latest\n  2. Download the latest version for your platform\n  3. Replace the binary: sudo cp <downloaded-file> %s\n  4. Restart the service: sudo systemctl restart crproxy", err, updateRepo, execPath)
	}

	// Windows 不支持原地更新（运行中的程序无法被替换）
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("Windows does not support in-place updates while running.\n\nPlease download manually:\nhttps://github.com/%s/releases/latest", updateRepo)
	}

	// 获取最新 release 信息
	apiURL := fmt.Sprintf("%s/repos/%s/releases/latest", updateAPIBase, updateRepo)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", updateUserAgent())

	client := &http.Client{Timeout: updateAPITimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to parse release info: %w", err)
	}

	latestVersion := release.TagName
	slog.Info("latest version available", "version", latestVersion)

	// 检查是否需要更新
	if latestVersion == version {
		return "", nil // 已是最新版本
	}

	// 确定平台和架构
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// 构建文件名
	assetName := fmt.Sprintf("crproxy-%s-%s", goos, goarch)
	if goos == "windows" {
		assetName += ".exe"
	}

	// 查找对应的资源
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.URL
			break
		}
	}

	if downloadURL == "" {
		return "", fmt.Errorf("no binary found for %s/%s\n\nPlease download manually:\nhttps://github.com/%s/releases/tag/%s", goos, goarch, updateRepo, latestVersion)
	}

	slog.Info("downloading new version", "url", downloadURL, "asset", assetName)

	// 下载新版本：显式设置超时与 UA，避免网络卡住导致请求永不返回
	downloadReq, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create download request: %w", err)
	}
	downloadReq.Header.Set("User-Agent", updateUserAgent())

	downloadClient := &http.Client{Timeout: updateDownloadTimeout}
	downloadResp, err := downloadClient.Do(downloadReq)
	if err != nil {
		return "", fmt.Errorf("failed to download binary: %w", err)
	}
	defer downloadResp.Body.Close()

	if downloadResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", downloadResp.StatusCode)
	}

	// 下载到运行目录同级
	newFile = filepath.Join(execDir, assetName+".new")
	updateProgress.beginDownload(latestVersion, downloadResp.ContentLength)

	out, err := os.OpenFile(newFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create file %s: %w", newFile, err)
	}

	written, err := copyWithProgress(out, downloadResp.Body)
	if err != nil {
		out.Close()
		return "", fmt.Errorf("failed to write binary: %w", err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return "", fmt.Errorf("failed to flush binary to disk: %w", err)
	}
	if err := out.Close(); err != nil {
		return "", fmt.Errorf("failed to close binary: %w", err)
	}

	// 长度对不上说明下载被截断
	if downloadResp.ContentLength > 0 && written != downloadResp.ContentLength {
		return "", fmt.Errorf("download incomplete: got %d bytes, expected %d", written, downloadResp.ContentLength)
	}

	slog.Info("new binary downloaded", "path", newFile, "bytes", written)

	// 校验确实是可执行文件，再动现有的二进制
	updateProgress.setStage(updateStageVerifying)
	if err := validateBinaryPayload(newFile, goos); err != nil {
		return "", err
	}

	// 删除旧备份（如果存在）
	updateProgress.setStage(updateStageBackingUp)
	backupPath := execPath + ".backup"
	os.Remove(backupPath)

	// 备份当前版本
	if err := os.Rename(execPath, backupPath); err != nil {
		return "", fmt.Errorf("failed to backup old binary: %w", err)
	}
	slog.Info("backup created", "path", backupPath)

	// 替换为新版本
	updateProgress.setStage(updateStageReplacing)
	if err := os.Rename(newFile, execPath); err != nil {
		// 尝试恢复备份
		if restoreErr := os.Rename(backupPath, execPath); restoreErr != nil {
			slog.Error("CRITICAL: failed to restore backup", "error", restoreErr, "backup_path", backupPath)
			return "", fmt.Errorf("CRITICAL: failed to replace binary and restore backup. Binary at: %s, Backup at: %s", newFile, backupPath)
		}
		return "", fmt.Errorf("failed to replace binary (restored from backup): %w", err)
	}
	installed = true

	return latestVersion, nil
}

// updateSelf 自升级到最新版本（命令行使用）
func updateSelf() error {
	latestVersion, err := performUpdate()
	if err != nil {
		return err
	}
	if latestVersion == "" {
		fmt.Printf("✅ Already at the latest version: %s\n", version)
		return nil
	}
	fmt.Printf("✅ Successfully updated to version %s\n", latestVersion)
	fmt.Println("⚠️  Please restart the service to use the new version")
	return nil
}
