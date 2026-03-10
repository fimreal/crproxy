package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

var version, buildTime string

const (
	// cacheWriteTimeout 缓存写入超时时间（5分钟，适合大文件）
	cacheWriteTimeout = 5 * time.Minute
	// maxRedirects 最大重定向次数
	maxRedirects = 10
	// metaSuffix 元数据文件后缀
	metaSuffix = ".meta"
	// blobSuffix 二进制文件后缀
	blobSuffix = ".blob"
	// tmpSuffix 临时文件后缀
	tmpSuffix = ".tmp"
)

// 日志级别
var logLevel = new(slog.LevelVar)

// initLogger 初始化结构化日志
func initLogger() {
	opts := &slog.HandlerOptions{Level: logLevel}
	handler := slog.NewJSONHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))
}

// setLogLevel 设置日志级别
func setLogLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "info":
		logLevel.Set(slog.LevelInfo)
	case "warn", "warning":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
	}
}

// generateRequestID 生成请求 ID
func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

//go:embed registrymap.json
var embedRegistryMap []byte

//go:embed admin/index.html
var adminHTML []byte

// RegistryMap 镜像仓库地址（使用 atomic.Value 实现线程安全的原子替换）
var registryMap atomic.Value

// GetRegistryMap 获取当前的 RegistryMap
func GetRegistryMap() map[string]string {
	if m, ok := registryMap.Load().(map[string]string); ok {
		return m
	}
	return make(map[string]string)
}

// SetRegistryMap 原子替换 RegistryMap
func SetRegistryMap(m map[string]string) {
	registryMap.Store(m)
}

// cacheMutex 缓存操作互斥锁（保护缓存清理和写入）
var cacheMutex sync.RWMutex

// CacheMeta 缓存元数据
type CacheMeta struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Size       int64             `json:"size"`
	Digest     string            `json:"digest"`
	Algorithm  string            `json:"algorithm"`
	CreatedAt  time.Time         `json:"createdAt"`
}

// loadRegistryMap 从文件或URL加载 RegistryMap
func loadRegistryMap(source string) (map[string]string, error) {
	var data []byte
	var err error

	// 如果没有指定源，则使用内置的 RegistryMap
	if source == "" {
		data = embedRegistryMap
		slog.Info("using built-in registry map")
	} else {
		// 从外部源加载 RegistryMap
		client := &http.Client{Timeout: 30 * time.Second}
		var resp *http.Response

		if strings.HasPrefix(source, "http") {
			resp, err = client.Get(source)
			if err != nil {
				return nil, fmt.Errorf("failed to load registry map from URL %s: %v", source, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("ERROR HTTP %d: %s", resp.StatusCode, resp.Status)
			}
			slog.Info("loaded registry map from URL", "source", source)
			data, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("ERROR failed to read response body: %v", err)
			}
		} else {
			// 从本地文件加载
			data, err = os.ReadFile(source)
			if err != nil {
				return nil, fmt.Errorf("ERROR failed to read registry map file %s: %v", source, err)
			}
			slog.Info("registry-map: loaded registry map from file", "source", source)
		}
	}

	// 解析JSON
	var registryMap map[string]string
	err = json.Unmarshal(data, &registryMap)
	if err != nil {
		return nil, fmt.Errorf("ERROR failed to parse registry map JSON: %v", err)
	}

	// 如果没有指定默认 registry，则任意选取其一
	if registryMap["default"] == "" && len(registryMap) > 0 {
		for k, v := range registryMap {
			if k != "default" && v != "" {
				// 验证 URL 格式
				if _, err := url.Parse(v); err == nil {
					registryMap["default"] = v
					break
				}
			}
		}
	}

	return registryMap, nil
}

var DomainSuffix string
var CacheDir string

// Config 动态配置结构
type Config struct {
	RegistryMap     map[string]string `json:"registryMap"`
	DefaultRegistry string            `json:"defaultRegistry"`
	DomainSuffix    string            `json:"domainSuffix"`
	LogLevel        string            `json:"logLevel"`
	CacheDir        string            `json:"cacheDir"`
	Listen          string            `json:"listen"`
	AdminPassword   string            `json:"adminPassword"`
}

// ConfigManager 配置管理器（线程安全）
type ConfigManager struct {
	mu       sync.RWMutex
	config   Config
	filePath string
}

// NewConfigManager 创建配置管理器
func NewConfigManager(filePath string) *ConfigManager {
	return &ConfigManager{
		filePath: filePath,
		config:   Config{RegistryMap: make(map[string]string)},
	}
}

// GetConfig 获取当前配置（返回副本）
func (cm *ConfigManager) GetConfig() Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// 返回副本，避免外部修改
	config := cm.config
	config.RegistryMap = make(map[string]string)
	for k, v := range cm.config.RegistryMap {
		config.RegistryMap[k] = v
	}
	return config
}

// UpdateConfig 更新配置
func (cm *ConfigManager) UpdateConfig(newConfig Config) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 验证配置
	if newConfig.DefaultRegistry != "" {
		if _, err := url.Parse(newConfig.DefaultRegistry); err != nil {
			return fmt.Errorf("invalid default-registry URL: %w", err)
		}
	}

	// 验证 RegistryMap 中的 URL
	for name, registryURL := range newConfig.RegistryMap {
		if _, err := url.Parse(registryURL); err != nil {
			return fmt.Errorf("invalid registry URL for %s: %w", name, err)
		}
	}

	// 更新内存配置
	cm.config = newConfig
	if cm.config.RegistryMap == nil {
		cm.config.RegistryMap = make(map[string]string)
	}

	// 持久化到文件
	if err := cm.saveToFile(); err != nil {
		slog.Error("failed to save config file", "error", err)
		return err
	}

	return nil
}

// LoadFromFile 从文件加载配置
func (cm *ConfigManager) LoadFromFile() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	data, err := os.ReadFile(cm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在不是错误
		}
		return err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	if config.RegistryMap == nil {
		config.RegistryMap = make(map[string]string)
	}

	cm.config = config
	return nil
}

// saveToFile 保存配置到文件（原子写入）
func (cm *ConfigManager) saveToFile() error {
	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return err
	}

	// 原子写入：先写临时文件，再 rename
	// 配置文件可能包含敏感信息，设置权限为 0600（仅所有者可读写）
	tmpFile := cm.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpFile, cm.filePath)
}

// AuthManager 认证管理器
type AuthManager struct {
	password string
	tokens   map[string]time.Time // token -> expiry
	mu       sync.RWMutex
}

// NewAuthManager 创建认证管理器
func NewAuthManager(password string) *AuthManager {
	am := &AuthManager{
		password: password,
		tokens:   make(map[string]time.Time),
	}

	// 启动定期清理过期 token 的任务
	if password != "" {
		go am.startCleanupTask()
	}

	return am
}

// startCleanupTask 定期清理过期 token（每小时清理一次）
func (am *AuthManager) startCleanupTask() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		am.mu.Lock()
		am.cleanExpiredTokens()
		am.mu.Unlock()
		slog.Debug("expired tokens cleaned")
	}
}

// Login 验证密码并生成 Token
func (am *AuthManager) Login(password string) (string, error) {
	if am.password == "" {
		return "", fmt.Errorf("admin password not configured")
	}

	if password != am.password {
		return "", fmt.Errorf("invalid password")
	}

	// 生成随机 token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := base64.StdEncoding.EncodeToString(tokenBytes)

	// 存储 token，有效期 24 小时
	am.mu.Lock()
	defer am.mu.Unlock()
	am.tokens[token] = time.Now().Add(24 * time.Hour)

	// 清理过期 token
	am.cleanExpiredTokens()

	return token, nil
}

// ValidateToken 验证 Token 是否有效
func (am *AuthManager) ValidateToken(authHeader string) bool {
	if am.password == "" {
		return false // 未设置密码，拒绝所有访问
	}

	// 解析 Authorization Header
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	am.mu.Lock()
	defer am.mu.Unlock()

	expiry, exists := am.tokens[token]
	if !exists {
		return false
	}

	// 检查是否过期，如果过期则删除
	if time.Now().After(expiry) {
		delete(am.tokens, token)
		return false
	}

	return true
}

// cleanExpiredTokens 清理过期 token（需要在锁内调用）
func (am *AuthManager) cleanExpiredTokens() {
	now := time.Now()
	for token, expiry := range am.tokens {
		if now.After(expiry) {
			delete(am.tokens, token)
		}
	}
}

// StatsCollector 统计收集器
type StatsCollector struct {
	totalRequests int64
	cacheHits     int64
	cacheMisses   int64
}

// NewStatsCollector 创建统计收集器
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{}
}

// IncrementRequests 增加请求计数
func (sc *StatsCollector) IncrementRequests() {
	atomic.AddInt64(&sc.totalRequests, 1)
}

// IncrementCacheHits 增加缓存命中计数
func (sc *StatsCollector) IncrementCacheHits() {
	atomic.AddInt64(&sc.cacheHits, 1)
}

// IncrementCacheMisses 增加缓存未命中计数
func (sc *StatsCollector) IncrementCacheMisses() {
	atomic.AddInt64(&sc.cacheMisses, 1)
}

// GetStats 获取统计数据
func (sc *StatsCollector) GetStats() map[string]int64 {
	return map[string]int64{
		"totalRequests": atomic.LoadInt64(&sc.totalRequests),
		"cacheHits":     atomic.LoadInt64(&sc.cacheHits),
		"cacheMisses":   atomic.LoadInt64(&sc.cacheMisses),
	}
}


// urlCache 缓存解析后的 URL，避免重复解析
var urlCache sync.Map // map[string]*url.URL

// getURLCached 获取缓存的 URL，如果不存在则解析并缓存
func getURLCached(urlStr string) (*url.URL, error) {
	if cached, ok := urlCache.Load(urlStr); ok {
		return cached.(*url.URL), nil
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	// 尝试存储到缓存（如果已有其他 goroutine 存储了，使用那个）
	actual, _ := urlCache.LoadOrStore(urlStr, u)
	return actual.(*url.URL), nil
}

func findRegistryURL(host string) (*url.URL, error) {
	registryMap := GetRegistryMap()

	if DomainSuffix != "" {
		// 当请求域名等于 DomainSuffix 时，使用默认 registry
		if DomainSuffix == host {
			if defaultRegistry := registryMap["default"]; defaultRegistry != "" {
				return getURLCached(defaultRegistry)
			}
		} else if suffix, found := strings.CutSuffix(host, "."+DomainSuffix); found {
			// 处理带前缀的镜像仓库域名
			registryURL := registryMap[suffix]
			if registryURL != "" {
				return getURLCached(registryURL)
			}
		}
	}
	return nil, fmt.Errorf("invalid registry [%s] given", host)
}

var tr = &http.Transport{
	MaxIdleConns:          100,
	IdleConnTimeout:       30 * time.Second,
	MaxIdleConnsPerHost:   10,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
	Proxy:                 http.ProxyFromEnvironment,
}

// redirectTransport 包装 Transport 以支持在代理内部处理重定向
type redirectTransport struct {
	transport http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 跟踪重定向次数
	redirectCount := 0
	currentReq := req

	for {
		// 执行原始请求
		resp, err := rt.transport.RoundTrip(currentReq)
		if err != nil {
			return nil, err
		}

		// 如果不是重定向响应，直接返回
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, nil
		}

		location := resp.Header.Get("Location")
		if location == "" {
			return resp, nil
		}

		redirectURL, err := url.Parse(location)
		if err != nil {
			return resp, nil // 返回原始响应，让客户端处理
		}

		// 如果重定向到相同的域名，返回响应让客户端处理
		if redirectURL.Host == currentReq.URL.Host {
			return resp, nil
		}

		// 检查重定向次数
		redirectCount++
		if redirectCount >= maxRedirects {
			slog.Warn("too many redirects, returning response to client", "count", redirectCount)
			return resp, nil
		}

		debugLog("following redirect", "count", redirectCount, "from", currentReq.URL.Host, "to", redirectURL.Host)

		// 关闭原始响应体
		resp.Body.Close()

		// 创建新的重定向请求（不能使用 req.Clone，因为会复制 RequestURI）
		var body io.Reader
		// 307和308重定向需要保持原始请求方法和请求体
		if (resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect) && currentReq.GetBody != nil {
			bodyCopy, err := currentReq.GetBody()
			if err == nil {
				defer bodyCopy.Close()
				body = bodyCopy
			}
		}
		redirectReq, err := http.NewRequest(currentReq.Method, location, body)
		if err != nil {
			slog.Error("failed to create redirect request", "error", err)
			return resp, nil // 返回原始响应
		}

		// 复制原始请求的头部（除了 Host）
		// 注意：不要复制 Authorization，因为 presigned URL 已经包含了签名，
		// 额外的 header 会导致签名验证失败（如 Cloudflare R2 等）
		for k, v := range currentReq.Header {
			// 跳过一些不应该复制的头部
			lowerKey := strings.ToLower(k)
			if lowerKey != "host" && lowerKey != "connection" && lowerKey != "authorization" {
				redirectReq.Header[k] = v
			}
		}

		// 设置 Host header
		redirectReq.Host = redirectURL.Host

		// 继续处理下一次重定向
		currentReq = redirectReq
	}
}

// isBlobRequest 检查是否是 blob 请求（只缓存 blobs，不缓存 manifests）
func isBlobRequest(path string) bool {
	// 只缓存 blobs（镜像层），不缓存 manifests（清单文件会更新）
	return strings.Contains(path, "/blobs/sha256:") ||
		strings.Contains(path, "/blobs/sha512:")
}

// extractDigestFromPath 从路径中提取 digest 算法和值
func extractDigestFromPath(path string) (algorithm string, digest string) {
	// 提取 sha256:<digest> 或 sha512:<digest>
	for _, prefix := range []string{"sha256:", "sha512:"} {
		idx := strings.Index(path, prefix)
		if idx != -1 {
			algorithm = strings.TrimSuffix(prefix, ":")
			digest = path[idx+len(prefix):]
			// 去掉可能的查询参数和路径分隔符
			digest = strings.Split(digest, "?")[0]
			digest = strings.Split(digest, "/")[0]
			return algorithm, digest
		}
	}
	return "", ""
}

// getCachePaths 根据 digest 获取缓存文件路径（返回元数据路径和blob路径）
func getCachePaths(digest string) (metaPath, blobPath string) {
	// 使用前两个字符作为子目录，避免单个目录文件过多
	if len(digest) < 2 {
		metaPath = filepath.Join(CacheDir, digest+metaSuffix)
		blobPath = filepath.Join(CacheDir, digest+blobSuffix)
		return
	}
	subDir := digest[:2]
	metaPath = filepath.Join(CacheDir, subDir, digest+metaSuffix)
	blobPath = filepath.Join(CacheDir, subDir, digest+blobSuffix)
	return
}

// readFromCache 从缓存读取响应（流式传输，不占用大量内存）
func readFromCache(c *gin.Context) bool {
	if CacheDir == "" {
		return false
	}

	// 只缓存 blobs
	if !isBlobRequest(c.Request.URL.Path) {
		return false
	}

	_, digest := extractDigestFromPath(c.Request.URL.Path)
	if digest == "" {
		return false
	}

	metaPath, blobPath := getCachePaths(digest)

	// 检查 blob 文件是否存在
	blobInfo, err := os.Stat(blobPath)
	if err != nil {
		return false
	}

	// 检查临时文件（正在写入中）
	tmpBlobPath := blobPath + tmpSuffix
	if tmpInfo, err := os.Stat(tmpBlobPath); err == nil {
		// 如果临时文件存在超过超时时间，清理它
		if time.Since(tmpInfo.ModTime()) > cacheWriteTimeout {
			tryRemoveFile(tmpBlobPath)
			tryRemoveFile(metaPath + tmpSuffix)
		}
		// 正在写入中，跳过缓存
		return false
	}

	// 读取元数据
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		tryRemoveFile(metaPath)
		tryRemoveFile(blobPath)
		return false
	}

	var meta CacheMeta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		slog.Warn("failed to unmarshal cache meta", "error", err)
		tryRemoveFile(metaPath)
		tryRemoveFile(blobPath)
		return false
	}

	// 验证 digest 是否匹配
	if meta.Digest != digest {
		slog.Warn("cache digest mismatch", "expected", digest, "got", meta.Digest)
		tryRemoveFile(metaPath)
		tryRemoveFile(blobPath)
		return false
	}

	// 设置响应头
	for k, v := range meta.Headers {
		c.Header(k, v)
	}
	c.Header("X-Cache", "HIT")
	c.Header("Content-Length", fmt.Sprintf("%d", blobInfo.Size()))

	// 打开 blob 文件进行流式传输
	blobFile, err := os.Open(blobPath)
	if err != nil {
		slog.Warn("failed to open cache blob", "error", err)
		return false
	}
	defer blobFile.Close()

	// 流式传输到客户端
	contentType := meta.Headers["Content-Type"]
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// 使用 bufio.Reader 进行带缓冲的读取，减少系统调用
	reader := bufio.NewReaderSize(blobFile, 32*1024) // 32KB buffer
	c.DataFromReader(meta.StatusCode, blobInfo.Size(), contentType, reader, nil)

	debugLog("DEBUG cache HIT: %s (size: %d)", c.Request.URL.Path, blobInfo.Size())
	return true
}

// tryRemoveFile 尝试删除文件，避免因文件不存在导致的错误日志
func tryRemoveFile(name string) error {
	err := os.Remove(name)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// cleanStaleTempFiles 清理过期的临时缓存文件
func cleanStaleTempFiles() {
	if CacheDir == "" {
		return
	}

	// 遍历缓存目录
	filepath.Walk(CacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		// 检查是否是临时文件
		if strings.HasSuffix(path, tmpSuffix) {
			// 如果文件存在时间超过超时时间，删除它
			if time.Since(info.ModTime()) > cacheWriteTimeout {
				if err := tryRemoveFile(path); err == nil {
					debugLog("DEBUG cleaned stale temp file: %s", path)
				}
			}
		}
		return nil
	})
}

// startCacheCleaner 启动定期清理过期临时文件的 goroutine
func startCacheCleaner() {
	if CacheDir == "" {
		return
	}

	// 启动时先清理一次
	cleanStaleTempFiles()

	// 启动定期清理
	go func() {
		ticker := time.NewTicker(cacheWriteTimeout)
		defer ticker.Stop()

		for range ticker.C {
			cleanStaleTempFiles()
		}
	}()
}

// streamingCacheWriter 流式缓存写入器，用于 TeeReader
type streamingCacheWriter struct {
	bufWriter   *bufio.Writer
	file        *os.File
	hasher      hash.Hash
	multiWriter io.Writer
	size        int64
}

func newStreamingCacheWriter(filePath string, algorithm string) (*streamingCacheWriter, error) {
	file, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}

	var hasher hash.Hash
	switch algorithm {
	case "sha256":
		hasher = sha256.New()
	case "sha512":
		hasher = sha512.New()
	default:
		hasher = sha256.New()
	}

	bufWriter := bufio.NewWriterSize(file, 64*1024)
	multiWriter := io.MultiWriter(bufWriter, hasher)

	return &streamingCacheWriter{
		bufWriter:   bufWriter,
		file:        file,
		hasher:      hasher,
		multiWriter: multiWriter,
	}, nil
}

func (w *streamingCacheWriter) Write(p []byte) (int, error) {
	n, err := w.multiWriter.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *streamingCacheWriter) Close() error {
	if err := w.bufWriter.Flush(); err != nil {
		return err
	}
	return w.file.Close()
}

func (w *streamingCacheWriter) Flush() error {
	return w.bufWriter.Flush()
}

func (w *streamingCacheWriter) Size() int64 {
	return w.size
}

func (w *streamingCacheWriter) Digest() string {
	return hex.EncodeToString(w.hasher.Sum(nil))
}

// cacheWriter 用于存储正在进行的缓存写入
type cacheWriter struct {
	writer     *streamingCacheWriter
	tmpPath    string
	metaPath   string
	blobPath   string
	algorithm  string
	digest     string
	headers    map[string]string
	statusCode int
	done       chan struct{}
	err        error
}

var activeCacheWrites sync.Map // map[digest]*cacheWriter

// teeReadCloser 包装 TeeReader 和原始 Closer
type teeReadCloser struct {
	io.Reader
	originalCloser io.Closer
	cw             *cacheWriter
}

func (t *teeReadCloser) Close() error {
	// 读取完成，触发缓存完成
	if t.cw != nil {
		close(t.cw.done)
	}
	if t.originalCloser != nil {
		return t.originalCloser.Close()
	}
	return nil
}

// writeToCache 准备流式缓存写入（在 ModifyResponse 中调用）
func writeToCache(resp *http.Response) {
	// 只缓存 GET 请求且状态码为 200 的响应
	if resp.Request.Method != "GET" || resp.StatusCode != http.StatusOK {
		return
	}

	// 只缓存 blobs
	if !isBlobRequest(resp.Request.URL.Path) {
		return
	}

	algorithm, digest := extractDigestFromPath(resp.Request.URL.Path)
	if digest == "" {
		return
	}

	metaPath, blobPath := getCachePaths(digest)
	tmpBlobPath := blobPath + tmpSuffix

	// 检查缓存文件是否已存在
	if _, err := os.Stat(blobPath); err == nil {
		return
	}

	// 检查是否已有相同 digest 正在写入
	if _, loaded := activeCacheWrites.LoadOrStore(digest, struct{}{}); loaded {
		return
	}

	// 创建目录
	cacheDir := filepath.Dir(blobPath)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		activeCacheWrites.Delete(digest)
		return
	}

	// 创建流式写入器
	writer, err := newStreamingCacheWriter(tmpBlobPath, algorithm)
	if err != nil {
		activeCacheWrites.Delete(digest)
		return
	}

	// 复制响应头
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			lowerKey := strings.ToLower(k)
			if lowerKey != "connection" && lowerKey != "transfer-encoding" {
				headers[k] = v[0]
			}
		}
	}

	cw := &cacheWriter{
		writer:     writer,
		tmpPath:    tmpBlobPath,
		metaPath:   metaPath,
		blobPath:   blobPath,
		algorithm:  algorithm,
		digest:     digest,
		headers:    headers,
		statusCode: resp.StatusCode,
		done:       make(chan struct{}),
	}

	// 包装响应体，使用 TeeReader 同时写入缓存
	originalBody := resp.Body
	teeReader := io.TeeReader(originalBody, writer)

	resp.Body = &teeReadCloser{
		Reader:         teeReader,
		originalCloser: originalBody,
		cw:             cw,
	}

	// 启动后台 goroutine 等待读取完成
	go func() {
		<-cw.done
		finishCacheWrite(digest, cw)
	}()
}

// finishCacheWrite 完成缓存写入
func finishCacheWrite(digest string, cw *cacheWriter) {
	defer activeCacheWrites.Delete(digest)

	if cw.writer == nil {
		return
	}

	// 刷新并关闭写入器
	if err := cw.writer.Flush(); err != nil {
		slog.Warn("failed to flush cache", "error", err)
		tryRemoveFile(cw.tmpPath)
		return
	}
	cw.writer.Close()

	// 验证哈希
	calculatedDigest := cw.writer.Digest()
	if calculatedDigest != cw.digest {
		slog.Warn("cache digest mismatch", "expected", cw.digest, "got", calculatedDigest)
		tryRemoveFile(cw.tmpPath)
		return
	}

	// 创建元数据
	meta := CacheMeta{
		StatusCode: cw.statusCode,
		Headers:    cw.headers,
		Size:       cw.writer.Size(),
		Digest:     calculatedDigest,
		Algorithm:  cw.algorithm,
		CreatedAt:  time.Now(),
	}

	metaData, err := json.Marshal(meta)
	if err != nil {
		slog.Warn("failed to marshal cache meta", "error", err)
		tryRemoveFile(cw.tmpPath)
		return
	}

	tmpMetaPath := cw.metaPath + tmpSuffix
	if err := os.WriteFile(tmpMetaPath, metaData, 0644); err != nil {
		slog.Warn("failed to write cache meta", "error", err)
		tryRemoveFile(cw.tmpPath)
		tryRemoveFile(tmpMetaPath)
		return
	}

	// 原子重命名
	if err := os.Rename(cw.tmpPath, cw.blobPath); err != nil {
		slog.Warn("failed to rename cache blob", "error", err)
		tryRemoveFile(cw.tmpPath)
		tryRemoveFile(tmpMetaPath)
		return
	}
	if err := os.Rename(tmpMetaPath, cw.metaPath); err != nil {
		slog.Warn("failed to rename cache meta", "error", err)
		tryRemoveFile(cw.metaPath)
	}

	debugLog("DEBUG cache saved: %s (size: %d)", cw.blobPath, cw.writer.Size())
}

// forward handles proxy requests
func forward(c *gin.Context) {
	// 检查缓存（仅对 GET 请求）
	if c.Request.Method == "GET" && CacheDir != "" {
		if readFromCache(c) {
			return
		}
	}

	// 预先检查registry是否存在（针对使用DomainSuffix的情况）
	if DomainSuffix != "" && strings.Contains(c.Request.Host, DomainSuffix) {
		_, err := findRegistryURL(c.Request.Host)
		if err != nil {
			slog.Error("registry not found for host", "host", c.Request.Host, "error", err)
			c.JSON(http.StatusNotFound, gin.H{
				"message": fmt.Sprintf("registry not found: %s, please visit /help for available registries", c.Request.Host),
			})
			return
		}
	}

	// handle proxy request
	proxy := httputil.ReverseProxy{
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			// 区分客户端断开和真正的代理错误
			if errors.Is(err, context.Canceled) {
				slog.Debug("client disconnected", "path", req.URL.Path)
				return
			}
			slog.Error("proxy error", "error", err)
			rw.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(rw, "Bad Gateway: %v", err)
		},
		Director: func(req *http.Request) {
			registryMap := GetRegistryMap()

			// 初始化请求的基本信息, 默认使用默认registry
			defaultURL, err := getURLCached(registryMap["default"])
			if err != nil {
				slog.Error("failed to parse default registry URL", "error", err)
				// 设置一个无效的 URL，让代理返回错误
				req.URL.Scheme = "invalid"
				req.URL.Host = "invalid"
				return
			}
			req.URL.Scheme = defaultURL.Scheme
			req.URL.Host = defaultURL.Host
			req.Host = defaultURL.Host

			// 检查是否为IP地址
			host := c.Request.Host
			if hostWithPort, _, err := net.SplitHostPort(c.Request.Host); err == nil {
				host = hostWithPort
			}

			if net.ParseIP(host) != nil {
				slog.Warn("client request host is IP address, using default upstream", "client_ip", c.ClientIP(), "host", c.Request.Host, "upstream", registryMap["default"])
			} else {
				u, err := findRegistryURL(c.Request.Host)
				if err != nil {
					slog.Warn("registry not found, using default", "host", c.Request.Host, "default", registryMap["default"])
				} else {
					req.URL.Scheme = u.Scheme
					req.URL.Host = u.Host
					req.Host = u.Host
				}
			}

			// 处理 token 路径
			if strings.HasPrefix(req.URL.Path, "/token/") {
				upstream := req.URL.Path[len("/token/"):]
				u, err := url.Parse(upstream)
				if err != nil {
					// 尝试修复被Nginx合并斜杠的URL：把 https:/xxx 变成 https://xxx
					if strings.HasPrefix(upstream, "http:/") && !strings.HasPrefix(upstream, "http://") {
						upstream = "http://" + upstream[len("http:/"):]
						u, err = url.Parse(upstream)
					} else if strings.HasPrefix(upstream, "https:/") && !strings.HasPrefix(upstream, "https://") {
						upstream = "https://" + upstream[len("https:/"):]
						u, err = url.Parse(upstream)
					}
					if err != nil {
						slog.Error("failed to parse token URL", "error", err)
						req.URL.Scheme = "invalid"
						req.URL.Host = "invalid"
						return
					}
				}
				// 验证 URL scheme，只允许 http 和 https
				if u.Scheme != "http" && u.Scheme != "https" {
					slog.Error("invalid token URL scheme", "scheme", u.Scheme)
					req.URL.Scheme = "invalid"
					req.URL.Host = "invalid"
					return
				}
				// 验证 Host 不为空
				if u.Host == "" {
					slog.Error("token URL has empty host")
					req.URL.Scheme = "invalid"
					req.URL.Host = "invalid"
					return
				}
				// 改过的 url 例如: http://127.0.0.1:5000/token/https://auth.docker.io/token?client_id=containerization-registry-client&service=registry.docker.io&scope=repository:library/alpine:pull
				// 需要修改为: https://auth.docker.io/token?client_id=containerization-registry-client&service=registry.docker.io&scope=repository:library/alpine:pull
				req.URL.Scheme = u.Scheme
				req.URL.Host = u.Host
				req.Host = u.Host
				req.URL.Path = u.Path
				if u.RawQuery != "" {
					req.URL.RawQuery = u.RawQuery
				}
			}

			debugLog("DEBUG %s %s -> %s://%s%s",
				c.Request.Method,
				c.Request.URL.RequestURI(),
				req.URL.Scheme,
				req.URL.Host,
				req.URL.RequestURI())
		},
		ModifyResponse: func(resp *http.Response) error {
			// 匿名请求遇到 401 时记录日志
			if resp.StatusCode == http.StatusUnauthorized {
				slog.Warn("proxy received 401 Unauthorized", "url", resp.Request.URL.String())
			}

			// 处理 Www-Authenticate header，修改 realm 地址到本服务
			if wwwAuth := resp.Header.Get("Www-Authenticate"); wwwAuth != "" {
				realmURL, ok := getRealm(wwwAuth)
				if !ok {
					slog.Error("failed to extract realm from Www-Authenticate header", "arg1", wwwAuth)
					return nil
				}

				// 修改 realm 地址到本服务
				reqScheme := "https"
				if c.Request.TLS == nil {
					reqScheme = "http"
				}
				reqHost := c.Request.Host
				// 把原始 realm 地址拼接到 /token/ 后
				proxyRealURL := fmt.Sprintf("%s://%s/token/%s", reqScheme, reqHost, realmURL)

				newWWWAuth := replaceRealm(wwwAuth, proxyRealURL)
				resp.Header.Set("Www-Authenticate", newWWWAuth)

				debugLog("DEBUG modified Www-Authenticate: %s", newWWWAuth)
			}

			// 写入缓存（同步读取响应体，异步写入文件）
			if CacheDir != "" {
				writeToCache(resp)
			}

			return nil
		},
		Transport: &redirectTransport{transport: tr},
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

var realmRe = regexp.MustCompile(`(?i)\brealm\s*=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,\s]+)`)

// getRealm 从 Www-Authenticate header 字符串中提取 realm 的值（不包含引号）
func getRealm(header string) (string, bool) {
	m := realmRe.FindStringSubmatch(header)
	if len(m) < 2 {
		return "", false
	}
	return strings.Trim(m[1], `"'`), true
}

// replaceRealm 用 newRealm 替换 header 中的 realm 值（返回新的 header 字符串）
func replaceRealm(header, newRealm string) string {
	return realmRe.ReplaceAllStringFunc(header, func(m string) string {
		return `realm="` + newRealm + `"`
	})
}

// Debug 是否开启调试日志（通过环境变量 DEBUG 控制）
var Debug = os.Getenv("DEBUG") == "1"

func debugLog(msg string, args ...any) {
	if Debug {
		slog.Debug(msg, args...)
	}
}

// requestIDMiddleware 请求 ID 中间件
func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		c.Set("requestID", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// accessLogMiddleware 访问日志中间件
func accessLogMiddleware(statsCollector *StatsCollector) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		// 处理请求
		c.Next()

		// 排除不需要统计和记录日志的路径
		excludePaths := []string{"/healthz", "/admin"}
		shouldSkip := false
		for _, excludePath := range excludePaths {
			if path == excludePath || strings.HasPrefix(path, excludePath+"/") {
				shouldSkip = true
				break
			}
		}

		if shouldSkip {
			return
		}

		// 收集统计数据
		if statsCollector != nil {
			statsCollector.IncrementRequests()
			cacheStatus := c.Writer.Header().Get("X-Cache")
			if cacheStatus == "HIT" {
				statsCollector.IncrementCacheHits()
			} else if cacheStatus == "MISS" {
				statsCollector.IncrementCacheMisses()
			}
		}

		// 记录访问日志
		latency := time.Since(start)
		status := c.Writer.Status()
		size := c.Writer.Size()
		requestID, _ := c.Get("requestID")
		cacheStatus := c.Writer.Header().Get("X-Cache")
		if cacheStatus == "" {
			cacheStatus = "BYPASS"
		}

		slog.Info("request",
			"request_id", requestID,
			"method", c.Request.Method,
			"path", path,
			"query", query,
			"status", status,
			"latency_ms", latency.Milliseconds(),
			"size", size,
			"client_ip", c.ClientIP(),
			"cache", cacheStatus,
		)
	}
}

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

// performUpdate 执行更新
func performUpdate() (string, error) {
	const repo = "fimreal/crproxy"

	// 获取当前可执行文件路径
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	slog.Info("checking for updates", "current_version", version, "executable", execPath)

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
		return "", fmt.Errorf("no binary found for %s/%s (looking for %s)", goos, goarch, assetName)
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

	// 创建临时文件
	tmpFile := execPath + ".new"
	out, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}

	// 复制文件内容
	if _, err := io.Copy(out, downloadResp.Body); err != nil {
		out.Close()
		os.Remove(tmpFile)
		return "", fmt.Errorf("failed to write binary: %w", err)
	}
	out.Close()

	// 备份旧版本
	backupPath := execPath + ".backup"
	if _, err := os.Stat(execPath); err == nil {
		if err := os.Rename(execPath, backupPath); err != nil {
			os.Remove(tmpFile)
			return "", fmt.Errorf("failed to backup old binary: %w", err)
		}
		slog.Info("backup created", "path", backupPath)
	}

	// 替换为新版本
	if err := os.Rename(tmpFile, execPath); err != nil {
		// 恢复备份
		if _, err := os.Stat(backupPath); err == nil {
			os.Rename(backupPath, execPath)
		}
		os.Remove(tmpFile)
		return "", fmt.Errorf("failed to replace binary: %w", err)
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

func main() {
	var help bool
	var showVersion bool
	var doUpdate bool
	var listen string
	var registryMapSource string
	var defaultRegistry string
	var logLevelStr string
	var configFile string

	flag.StringVar(&listen, "listen", ":5000", "backend listen address")
	flag.StringVar(&DomainSuffix, "domain-suffix", "", "domain suffix for mirror hosts, e.g. mydomain.com; if empty use default registry as upstream")
	flag.StringVar(&registryMapSource, "registry-map", "", "registry map file path or URL (default: embed registrymap.json)")
	flag.StringVar(&CacheDir, "cache-dir", "", "local cache directory for caching responses (optional, disabled if empty)")
	flag.BoolVar(&help, "help", false, "show help")
	flag.StringVar(&defaultRegistry, "default-registry", "", "default registry to use when no domain suffix is configured or when accessing via IP address")
	flag.BoolVar(&showVersion, "version", false, "show version")
	flag.StringVar(&logLevelStr, "log-level", "info", "log level: debug, info, warn, error")
	flag.StringVar(&configFile, "config-file", "", "configuration file path (default: ./crproxy-config.json)")
	flag.BoolVar(&doUpdate, "update", false, "update to latest version from GitHub releases")
	flag.Parse()

	// 初始化日志
	initLogger()
	setLogLevel(logLevelStr)

	if showVersion {
		fmt.Printf("version: %s, build time: %s\n", version, buildTime)
		return
	}

	if help {
		flag.Usage()
		return
	}

	// 自升级
	if doUpdate {
		if err := updateSelf(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Update failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 初始化配置管理器
	if configFile == "" {
		configFile = "crproxy-config.json"
	}
	configManager := NewConfigManager(configFile)

	// 尝试加载配置文件
	if err := configManager.LoadFromFile(); err != nil {
		slog.Error("failed to load config file", "error", err)
		os.Exit(1)
	}

	// 使用命令行参数创建初始配置
	initialConfig := Config{
		RegistryMap:     make(map[string]string),
		DefaultRegistry: defaultRegistry,
		DomainSuffix:    DomainSuffix,
		LogLevel:        logLevelStr,
		CacheDir:        CacheDir,
		Listen:          listen,
	}

	// 如果配置文件为空，使用命令行参数初始化
	loadedConfig := configManager.GetConfig()
	if len(loadedConfig.RegistryMap) == 0 {
		// 加载RegistryMap
		var err error
		registryMap, err := loadRegistryMap(registryMapSource)
		if err != nil {
			slog.Error("Failed to load registry map", "error", err)
			os.Exit(1)
		}
		initialConfig.RegistryMap = registryMap
		configManager.UpdateConfig(initialConfig)
	} else {
		// 配置文件存在，使用配置文件的值，但命令行参数优先
		if defaultRegistry != "" {
			loadedConfig.DefaultRegistry = defaultRegistry
		}
		if DomainSuffix != "" {
			loadedConfig.DomainSuffix = DomainSuffix
		}
		if logLevelStr != "info" {
			loadedConfig.LogLevel = logLevelStr
		}
		if CacheDir != "" {
			loadedConfig.CacheDir = CacheDir
		}
		if listen != ":5000" {
			loadedConfig.Listen = listen
		}
		configManager.UpdateConfig(loadedConfig)
	}

	// 应用配置
	config := configManager.GetConfig()
	SetRegistryMap(config.RegistryMap)
	DomainSuffix = config.DomainSuffix
	CacheDir = config.CacheDir
	setLogLevel(config.LogLevel)

	debugLog("DEBUG registry-map: available registries: %v", GetRegistryMap())

	// 初始化缓存目录
	if CacheDir != "" {
		if err := os.MkdirAll(CacheDir, 0755); err != nil {
			slog.Error("failed to create cache directory", "cache_dir", CacheDir, "error", err)
			os.Exit(1)
		}

		slog.Info("cache enabled", "cache_dir", CacheDir)
		// 启动缓存清理器（清理崩溃遗留的临时文件）
		startCacheCleaner()
	} else {
		slog.Info("cache disabled")
	}

	// 初始化认证管理器（优先使用配置文件中的密码，环境变量作为备选）
	adminPassword := configManager.GetConfig().AdminPassword
	if adminPassword == "" {
		adminPassword = os.Getenv("ADMIN_PASSWORD")
	}
	authManager := NewAuthManager(adminPassword)
	if adminPassword == "" {
		slog.Warn("adminPassword not set in config or ADMIN_PASSWORD env, admin interface will be disabled")
	} else {
		slog.Info("admin interface enabled")
	}

	// 初始化统计收集器
	statsCollector := NewStatsCollector()

	if !Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestIDMiddleware())
	r.Use(accessLogMiddleware(statsCollector))

	// 原有的 API 路由
	r.Any("/v2/*path", forward)
	r.Any("/token/*path", forward)

	r.GET("/help", func(c *gin.Context) {
		c.JSON(http.StatusOK, GetRegistryMap())
	})
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	// 管理界面 API
	// 登录速率限制器：每秒最多 5 次登录尝试
	loginLimiter := rate.NewLimiter(rate.Every(time.Second/5), 5)

	// 登录接口（无需认证）
	r.POST("/admin/api/login", func(c *gin.Context) {
		// 检查速率限制
		if !loginLimiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many login attempts. Please wait."})
			return
		}

		if authManager.password == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin interface is disabled. Set ADMIN_PASSWORD environment variable to enable."})
			return
		}

		var req struct {
			Password string `json:"password"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		token, err := authManager.Login(req.Password)
		if err != nil {
			slog.Warn("login failed", "client_ip", c.ClientIP(), "error", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			return
		}

		slog.Info("login successful", "client_ip", c.ClientIP())
		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	// 认证中间件
	authMiddlewareFunc := func(c *gin.Context) {
		if authManager.password == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin interface is disabled"})
			c.Abort()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if !authManager.ValidateToken(authHeader) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}

	// 管理 API 路由组（需要认证）
	adminAPI := r.Group("/admin/api")
	adminAPI.Use(authMiddlewareFunc)
	{
		// 获取配置
		adminAPI.GET("/config", func(c *gin.Context) {
			config := configManager.GetConfig()
			c.JSON(http.StatusOK, config)
		})

		// 更新配置
		adminAPI.PUT("/config", func(c *gin.Context) {
			var newConfig Config
			if err := c.BindJSON(&newConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
				return
			}

			if err := configManager.UpdateConfig(newConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			// 应用配置（实时生效）
			SetRegistryMap(newConfig.RegistryMap)
			DomainSuffix = newConfig.DomainSuffix
			setLogLevel(newConfig.LogLevel)

			slog.Info("config updated", "client_ip", c.ClientIP())
			c.JSON(http.StatusOK, gin.H{"message": "Configuration updated successfully"})
		})

		// 添加 registry 映射
		adminAPI.POST("/registry", func(c *gin.Context) {
			var req struct {
				Name string `json:"name"`
				URL  string `json:"url"`
			}
			if err := c.BindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
				return
			}

			if req.Name == "" || req.URL == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Name and URL are required"})
				return
			}

			// 验证 URL
			if _, err := url.Parse(req.URL); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid URL"})
				return
			}

			// 更新配置
			config := configManager.GetConfig()
			if config.RegistryMap == nil {
				config.RegistryMap = make(map[string]string)
			}
			config.RegistryMap[req.Name] = req.URL

			if err := configManager.UpdateConfig(config); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			// 应用配置
			SetRegistryMap(config.RegistryMap)

			slog.Info("registry added", "name", req.Name, "url", req.URL)
			c.JSON(http.StatusOK, gin.H{"message": "Registry added successfully"})
		})

		// 删除 registry 映射
		adminAPI.DELETE("/registry/:name", func(c *gin.Context) {
			name := c.Param("name")

			if name == "default" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete default registry"})
				return
			}

			config := configManager.GetConfig()
			if _, exists := config.RegistryMap[name]; !exists {
				c.JSON(http.StatusNotFound, gin.H{"error": "Registry not found"})
				return
			}

			delete(config.RegistryMap, name)
			if err := configManager.UpdateConfig(config); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			// 应用配置
			SetRegistryMap(config.RegistryMap)

			slog.Info("registry deleted", "name", name)
			c.JSON(http.StatusOK, gin.H{"message": "Registry deleted successfully"})
		})

		// 获取统计
		adminAPI.GET("/stats", func(c *gin.Context) {
			stats := statsCollector.GetStats()
			c.JSON(http.StatusOK, stats)
		})

		// 获取缓存统计
		adminAPI.GET("/cache/stats", func(c *gin.Context) {
			if CacheDir == "" {
				c.JSON(http.StatusOK, gin.H{
					"enabled": false,
				})
				return
			}

			var totalSize int64
			var fileCount int
			err := filepath.Walk(CacheDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					totalSize += info.Size()
					fileCount++
				}
				return nil
			})

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"enabled":   true,
				"dir":       CacheDir,
				"totalSize": totalSize,
				"fileCount": fileCount,
			})
		})

		// 清空缓存
		adminAPI.POST("/cache/clear", func(c *gin.Context) {
			if CacheDir == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cache not enabled"})
				return
			}

			// 加锁保护缓存清理操作
			cacheMutex.Lock()
			defer cacheMutex.Unlock()

			files, err := os.ReadDir(CacheDir)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			var deleted int
			var errors []string
			for _, file := range files {
				if err := os.RemoveAll(filepath.Join(CacheDir, file.Name())); err != nil {
					errors = append(errors, err.Error())
				} else {
					deleted++
				}
			}

			slog.Info("cache cleared", "deleted_files", deleted, "errors", len(errors))
			c.JSON(http.StatusOK, gin.H{
				"deleted": deleted,
				"errors":  errors,
			})
		})

		// 检查更新
		adminAPI.GET("/update/check", func(c *gin.Context) {
			info, err := checkForUpdate()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, info)
		})

		// 执行更新
		adminAPI.POST("/update", func(c *gin.Context) {
			latestVersion, err := performUpdate()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			if latestVersion == "" {
				c.JSON(http.StatusOK, gin.H{
					"message":        "Already at the latest version",
					"currentVersion": version,
				})
				return
			}
			slog.Info("binary updated", "new_version", latestVersion, "client_ip", c.ClientIP())
			c.JSON(http.StatusOK, gin.H{
				"message":        "Update successful. Please restart the service.",
				"currentVersion": version,
				"newVersion":     latestVersion,
			})
		})
	}

	// 管理界面前端页面
	r.GET("/admin", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", adminHTML)
	})
	r.GET("/admin/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", adminHTML)
	})

	slog.Info("crproxy listening", "address", listen)
	if DomainSuffix != "" {
		slog.Info("domain-suffix configured", "suffix", DomainSuffix)
	} else {
		slog.Warn("domain-suffix is not set, using default registry as the solo upstream")
	}
	if err := r.Run(listen); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

