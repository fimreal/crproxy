package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// cacheWriteTimeout 缓存写入超时时间（5分钟，适合大文件）
	cacheWriteTimeout = 5 * time.Minute
	// metaSuffix 元数据文件后缀
	metaSuffix = ".meta"
	// blobSuffix 二进制文件后缀
	blobSuffix = ".blob"
	// tmpSuffix 临时文件后缀
	tmpSuffix = ".tmp"
)

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

// activeCacheWrites 正在进行的缓存写入
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
