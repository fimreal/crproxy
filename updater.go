package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// 用于检测是否需要重启
var (
	initialBinaryModTime time.Time
	initialBinaryPath    string
)

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
	const repo = "fimreal/crproxy"

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
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

	// 如果可执行文件已存在，检查是否可写
	if _, err := os.Stat(execPath); err == nil {
		// 尝试打开文件以写入模式
		f, err := os.OpenFile(execPath, os.O_WRONLY, 0)
		if err != nil {
			if os.IsPermission(err) {
				return fmt.Errorf("no write permission to executable %s (permission denied)", execPath)
			}
			return fmt.Errorf("cannot write to executable %s: %w", execPath, err)
		}
		f.Close()
	}

	return nil
}

// recordStartupBinaryInfo 记录启动时的二进制文件信息
func recordStartupBinaryInfo() error {
	execPath, err := os.Executable()
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

	execPath, err := os.Executable()
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

// performUpdate 执行更新
func performUpdate() (string, error) {
	const repo = "fimreal/crproxy"

	// 获取当前可执行文件路径
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	execDir := filepath.Dir(execPath)
	slog.Info("checking for updates", "current_version", version, "executable", execPath)

	// 先检查写入权限（避免无意义的下载）
	if err := checkWritePermission(execPath); err != nil {
		return "", fmt.Errorf("no write permission for in-place update: %w\n\nPlease update manually:\n  1. Visit: https://github.com/%s/releases/latest\n  2. Download the latest version for your platform\n  3. Replace the binary: sudo cp <downloaded-file> %s\n  4. Restart the service: sudo systemctl restart crproxy", err, repo, execPath)
	}

	// Windows 不支持原地更新（运行中的程序无法被替换）
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("Windows does not support in-place updates while running.\n\nPlease download manually:\nhttps://github.com/%s/releases/latest", repo)
	}

	// 获取最新 release 信息
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
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
		return "", fmt.Errorf("no binary found for %s/%s\n\nPlease download manually:\nhttps://github.com/%s/releases/tag/%s", goos, goarch, repo, latestVersion)
	}

	slog.Info("downloading new version", "url", downloadURL, "asset", assetName)

	// 下载新版本
	downloadResp, err := http.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download binary: %w", err)
	}
	defer downloadResp.Body.Close()

	if downloadResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", downloadResp.StatusCode)
	}

	// 下载到运行目录同级
	newFile := filepath.Join(execDir, assetName+".new")
	out, err := os.OpenFile(newFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create file %s: %w", newFile, err)
	}

	// 复制文件内容
	_, err = io.Copy(out, downloadResp.Body)
	if err != nil {
		out.Close()
		os.Remove(newFile)
		return "", fmt.Errorf("failed to write binary: %w", err)
	}
	out.Close()

	slog.Info("new binary downloaded", "path", newFile)

	// 删除旧备份（如果存在）
	backupPath := execPath + ".backup"
	os.Remove(backupPath)

	// 备份当前版本
	if err := os.Rename(execPath, backupPath); err != nil {
		os.Remove(newFile)
		return "", fmt.Errorf("failed to backup old binary: %w", err)
	}
	slog.Info("backup created", "path", backupPath)

	// 替换为新版本
	if err := os.Rename(newFile, execPath); err != nil {
		// 尝试恢复备份
		if restoreErr := os.Rename(backupPath, execPath); restoreErr != nil {
			slog.Error("CRITICAL: failed to restore backup", "error", restoreErr, "backup_path", backupPath)
			return "", fmt.Errorf("CRITICAL: failed to replace binary and restore backup. Binary at: %s, Backup at: %s", newFile, backupPath)
		}
		os.Remove(newFile)
		return "", fmt.Errorf("failed to replace binary (restored from backup): %w", err)
	}

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
