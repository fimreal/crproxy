package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
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

//go:embed registrymap.json
var embedRegistryMap []byte

// RegistryMap 镜像仓库地址
var RegistryMap map[string]string

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
		log.Printf("INFO registry-map: using built-in registry map")
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
			log.Printf("INFO registry-map: loaded registry map from URL: %s", source)
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
			log.Printf("INFO registry-map: loaded registry map from file: %s", source)
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
	if DomainSuffix != "" {
		// 当请求域名等于 DomainSuffix 时，使用默认 registry
		if DomainSuffix == host {
			if defaultRegistry := RegistryMap["default"]; defaultRegistry != "" {
				return getURLCached(defaultRegistry)
			}
		} else if suffix, found := strings.CutSuffix(host, "."+DomainSuffix); found {
			// 处理带前缀的镜像仓库域名
			registryURL := RegistryMap[suffix]
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
			log.Printf("WARNING too many redirects (%d), returning response to client", redirectCount)
			return resp, nil
		}

		debugLog("DEBUG following redirect #%d: %s -> %s", redirectCount, currentReq.URL.Host, redirectURL.Host)

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
			log.Printf("ERROR failed to create redirect request: %v", err)
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
		log.Printf("WARNING failed to unmarshal cache meta: %v", err)
		tryRemoveFile(metaPath)
		tryRemoveFile(blobPath)
		return false
	}

	// 验证 digest 是否匹配
	if meta.Digest != digest {
		log.Printf("WARNING cache digest mismatch: expected %s, got %s", digest, meta.Digest)
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
		log.Printf("WARNING failed to open cache blob: %v", err)
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

// acquireCacheLock 尝试获取缓存目录的锁，防止多实例共享
// 返回释放锁的函数
func acquireCacheLock() (func(), error) {
	if CacheDir == "" {
		return func() {}, nil
	}

	lockFile := filepath.Join(CacheDir, ".lock")

	// 尝试创建锁文件（排他创建）
	f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		if os.IsExist(err) {
			// 锁文件已存在，读取其中的 PID
			data, readErr := os.ReadFile(lockFile)
			if readErr == nil {
				return nil, fmt.Errorf("cache directory is already in use by process %s (PID: %s). Each instance must use a separate cache directory", strings.TrimSpace(string(data)), strings.TrimSpace(string(data)))
			}
			return nil, fmt.Errorf("cache directory is already in use by another instance. Each instance must use a separate cache directory")
		}
		return nil, fmt.Errorf("failed to create lock file: %v", err)
	}

	// 写入当前进程 PID
	fmt.Fprintf(f, "%d\n", os.Getpid())
	f.Close()

	// 返回释放函数
	return func() {
		tryRemoveFile(lockFile)
	}, nil
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
		log.Printf("WARNING failed to flush cache: %v", err)
		tryRemoveFile(cw.tmpPath)
		return
	}
	cw.writer.Close()

	// 验证哈希
	calculatedDigest := cw.writer.Digest()
	if calculatedDigest != cw.digest {
		log.Printf("WARNING cache digest mismatch: expected %s, got %s", cw.digest, calculatedDigest)
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
		log.Printf("WARNING failed to marshal cache meta: %v", err)
		tryRemoveFile(cw.tmpPath)
		return
	}

	tmpMetaPath := cw.metaPath + tmpSuffix
	if err := os.WriteFile(tmpMetaPath, metaData, 0644); err != nil {
		log.Printf("WARNING failed to write cache meta: %v", err)
		tryRemoveFile(cw.tmpPath)
		tryRemoveFile(tmpMetaPath)
		return
	}

	// 原子重命名
	if err := os.Rename(cw.tmpPath, cw.blobPath); err != nil {
		log.Printf("WARNING failed to rename cache blob: %v", err)
		tryRemoveFile(cw.tmpPath)
		tryRemoveFile(tmpMetaPath)
		return
	}
	if err := os.Rename(tmpMetaPath, cw.metaPath); err != nil {
		log.Printf("WARNING failed to rename cache meta: %v", err)
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
			log.Printf("ERROR registry not found for host %s: %v", c.Request.Host, err)
			c.JSON(http.StatusNotFound, gin.H{
				"message": fmt.Sprintf("registry not found: %s, please visit /help for available registries", c.Request.Host),
			})
			return
		}
	}

	// handle proxy request
	proxy := httputil.ReverseProxy{
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			log.Printf("ERROR proxy error: %v", err)
			rw.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(rw, "Bad Gateway: %v", err)
		},
		Director: func(req *http.Request) {
			// 初始化请求的基本信息, 默认使用默认registry
			defaultURL, err := getURLCached(RegistryMap["default"])
			if err != nil {
				log.Printf("ERROR failed to parse default registry URL: %v", err)
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
				log.Printf("WARNING client %s request host is IP address %s, use default upstream: %s", c.ClientIP(), c.Request.Host, RegistryMap["default"])
			} else {
				u, err := findRegistryURL(c.Request.Host)
				if err != nil {
					log.Printf("WARNING registry not found for %s, using default: %s", c.Request.Host, RegistryMap["default"])
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
						log.Printf("ERROR failed to parse token URL: %v", err)
						req.URL.Scheme = "invalid"
						req.URL.Host = "invalid"
						return
					}
				}
				// 验证 URL scheme，只允许 http 和 https
				if u.Scheme != "http" && u.Scheme != "https" {
					log.Printf("ERROR invalid token URL scheme: %s", u.Scheme)
					req.URL.Scheme = "invalid"
					req.URL.Host = "invalid"
					return
				}
				// 验证 Host 不为空
				if u.Host == "" {
					log.Printf("ERROR token URL has empty host")
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
				log.Printf("WARNING proxy received 401 Unauthorized: %s", resp.Request.URL.String())
			}

			// 处理 Www-Authenticate header，修改 realm 地址到本服务
			if wwwAuth := resp.Header.Get("Www-Authenticate"); wwwAuth != "" {
				realmURL, ok := getRealm(wwwAuth)
				if !ok {
					log.Printf("ERROR failed to extract realm from Www-Authenticate header: %v", wwwAuth)
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

func debugLog(format string, args ...interface{}) {
	if Debug {
		log.Printf(format, args...)
	}
}

func main() {
	var help bool
	var showVersion bool
	var listen string
	var registryMapSource string
	var defaultRegistry string

	flag.StringVar(&listen, "listen", ":5000", "backend listen address")
	flag.StringVar(&DomainSuffix, "domain-suffix", "", "domain suffix for mirror hosts, e.g. mydomain.com; if empty use default registry as upstream")
	flag.StringVar(&registryMapSource, "registry-map", "", "registry map file path or URL (default: embed registrymap.json)")
	flag.StringVar(&CacheDir, "cache-dir", "", "local cache directory for caching responses (optional, disabled if empty)")
	flag.BoolVar(&help, "help", false, "show help")
	flag.StringVar(&defaultRegistry, "default-registry", "", "default registry to use when no domain suffix is configured or when accessing via IP address")
	flag.BoolVar(&showVersion, "version", false, "show version")
	flag.Parse()

	if showVersion {
		fmt.Printf("version: %s, build time: %s\n", version, buildTime)
		return
	}

	if help {
		flag.Usage()
		return
	}

	// 加载RegistryMap
	var err error
	RegistryMap, err = loadRegistryMap(registryMapSource)
	if err != nil {
		log.Fatalf("ERROR Failed to load registry map: %v", err)
	}

	if defaultRegistry != "" {
		// 验证 default registry URL 格式
		if _, err := url.Parse(defaultRegistry); err != nil {
			log.Fatalf("ERROR invalid default-registry URL: %v", err)
		}
		RegistryMap["default"] = defaultRegistry
		log.Printf("INFO default-registry set to: %s", defaultRegistry)
	}
	debugLog("DEBUG registry-map: available registries: %v", RegistryMap)

	// 初始化缓存目录
	if CacheDir != "" {
		if err := os.MkdirAll(CacheDir, 0755); err != nil {
			log.Fatalf("ERROR failed to create cache directory %s: %v", CacheDir, err)
		}

		// 获取缓存目录锁，防止多实例共享
		releaseLock, err := acquireCacheLock()
		if err != nil {
			log.Fatalf("ERROR %v", err)
		}
		defer releaseLock()

		log.Printf("INFO cache: enabled, cache directory: %s", CacheDir)
		// 启动缓存清理器（清理崩溃遗留的临时文件）
		startCacheCleaner()
	} else {
		log.Printf("INFO cache: disabled")
	}

	if !Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())

	r.Any("/v2/*path", forward)
	r.Any("/token/*path", forward)

	r.GET("/help", func(c *gin.Context) {
		log.Printf("INFO client %s request help information", c.ClientIP())
		c.JSON(http.StatusOK, RegistryMap)
	})
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	log.Printf("INFO crproxy listening on %s", listen)
	if DomainSuffix != "" {
		log.Printf("INFO domain-suffix: %q", DomainSuffix)
	} else {
		log.Printf("WARNING domain-suffix is not set, using default registry as the solo upstream")
	}
	log.Fatal(r.Run(listen))
}
