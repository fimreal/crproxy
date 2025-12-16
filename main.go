package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
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
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// cacheWriteTimeout 缓存写入超时时间（5分钟，适合大文件）
	cacheWriteTimeout = 5 * time.Minute
)

//go:embed registrymap.json
var embedRegistryMap []byte

// RegistryMap 镜像仓库地址
var RegistryMap map[string]string

// debugEnabled 是否开启调试日志（通过环境变量 CRPROXY_DEBUG 控制）
var debugEnabled = os.Getenv("CRPROXY_DEBUG") == "1"

func debugLog(format string, args ...interface{}) {
	if debugEnabled {
		log.Printf(format, args...)
	}
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

	debugLog("DEBUG registry-map: available registries: %v", registryMap)
	return registryMap, nil
}

var DomainSuffix string
var CacheDir string

func findRegistryURL(host string) (*url.URL, error) {
	if DomainSuffix != "" {
		// 当请求域名等于 DomainSuffix 时，使用默认 registry
		if DomainSuffix == host {
			if defaultRegistry := RegistryMap["default"]; defaultRegistry != "" {
				return url.Parse(defaultRegistry)
			}
		} else if strings.HasSuffix(host, "."+DomainSuffix) {
			// 处理带前缀的镜像仓库域名
			registry := strings.TrimSuffix(host, "."+DomainSuffix)
			registryURL := RegistryMap[registry]
			if registryURL != "" {
				return url.Parse(registryURL)
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

// getCacheKey 根据请求生成缓存键
func getCacheKey(req *http.Request) string {
	key := req.Method + ":" + req.URL.String()
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// getCachePath 获取缓存文件路径
func getCachePath(cacheKey string) string {
	// 使用前两个字符作为子目录，避免单个目录文件过多
	subDir := cacheKey[:2]
	return filepath.Join(CacheDir, subDir, cacheKey)
}

// getDigestCachePath 根据digest获取缓存文件路径
func getDigestCachePath(digest string) string {
	// 使用前两个字符作为子目录，避免单个目录文件过多
	subDir := digest[:2]
	return filepath.Join(CacheDir, subDir, digest)
}

// isDigestRequest 检查是否是 digest 请求（基于内容寻址，永久有效）
func isDigestRequest(path string) bool {
	// 检查路径中是否包含 sha256: 或 sha512: 等 digest
	// 格式通常是: /v2/<repo>/blobs/sha256:<digest> 或 /v2/<repo>/manifests/sha256:<digest>
	return strings.Contains(path, "/blobs/sha256:") ||
		strings.Contains(path, "/blobs/sha512:") ||
		strings.Contains(path, "/manifests/sha256:") ||
		strings.Contains(path, "/manifests/sha512:")
}

// extractDigestFromPath 从路径中提取 digest 值
func extractDigestFromPath(path string) string {
	// 提取 sha256:<digest> 或 sha512:<digest>
	parts := strings.Split(path, "sha256:")
	if len(parts) > 1 {
		// 取第一部分（去掉可能的查询参数）
		digest := strings.Split(parts[1], "?")[0]
		digest = strings.Split(digest, "/")[0]
		return digest
	}
	parts = strings.Split(path, "sha512:")
	if len(parts) > 1 {
		digest := strings.Split(parts[1], "?")[0]
		digest = strings.Split(digest, "/")[0]
		return digest
	}
	return ""
}

// getCacheMarkerPath 获取缓存标记文件路径（隐藏文件）
func getCacheMarkerPath(cacheKey string) string {
	cachePath := getCachePath(cacheKey)
	return cachePath + ".writing"
}

// getDigestCacheMarkerPath 获取digest缓存标记文件路径
func getDigestCacheMarkerPath(digest string) string {
	cachePath := getDigestCachePath(digest)
	return cachePath + ".writing"
}

// isCacheWriting 检查缓存是否正在写入中
func isCacheWriting(cacheKey string) (bool, time.Time) {
	markerPath := getCacheMarkerPath(cacheKey)
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return false, time.Time{}
	}

	// 解析时间戳
	var timestamp int64
	if err := json.Unmarshal(data, &timestamp); err != nil {
		return false, time.Time{}
	}

	return true, time.Unix(0, timestamp)
}

// isDigestCacheWriting 检查digest缓存是否正在写入中
func isDigestCacheWriting(digest string) (bool, time.Time) {
	markerPath := getDigestCacheMarkerPath(digest)
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return false, time.Time{}
	}

	// 解析时间戳
	var timestamp int64
	if err := json.Unmarshal(data, &timestamp); err != nil {
		return false, time.Time{}
	}

	return true, time.Unix(0, timestamp)
}

// readFromCache 从缓存读取响应
func readFromCache(c *gin.Context, cacheKey string) bool {
	if CacheDir == "" {
		return false
	}

	// 确定缓存路径和标记路径
	digest := extractDigestFromPath(c.Request.URL.Path)
	var cachePath, markerPath string
	if digest != "" {
		cachePath = getDigestCachePath(digest)
		markerPath = getDigestCacheMarkerPath(digest)
	} else {
		cachePath = getCachePath(cacheKey)
		markerPath = getCacheMarkerPath(cacheKey)
	}

	// 检查缓存文件是否存在
	info, err := os.Stat(cachePath)
	if err != nil {
		return false
	}

	// 检查写入标记
	var writing bool
	var writeTime time.Time
	if digest != "" {
		writing, writeTime = isDigestCacheWriting(digest)
	} else {
		writing, writeTime = isCacheWriting(cacheKey)
	}

	if writing {
		if time.Since(writeTime) > cacheWriteTimeout {
			log.Printf("WARNING cache write timeout, cleaning up: %s", cachePath)
			tryRemoveFile(cachePath)
			tryRemoveFile(markerPath)
		}
		return false
	}

	// 检查非 digest 缓存是否过期（7天）
	if !isDigestRequest(c.Request.URL.Path) && time.Since(info.ModTime()) > 7*24*time.Hour {
		tryRemoveFile(cachePath)
		return false
	}

	// 读取缓存文件
	data, err := os.ReadFile(cachePath)
	if err != nil {
		log.Printf("WARNING failed to read cache file: %v", err)
		return false
	}

	if len(data) == 0 {
		log.Printf("WARNING cache file is empty, removing: %s", cachePath)
		if time.Since(info.ModTime()) > 10*time.Minute {
			tryRemoveFile(cachePath)
		}
		return false
	}

	// 解析缓存响应
	var cachedResp struct {
		StatusCode int               `json:"statusCode"`
		Headers    map[string]string `json:"headers"`
		Body       []byte            `json:"body"`
	}
	if err := json.Unmarshal(data, &cachedResp); err != nil {
		log.Printf("WARNING failed to unmarshal cache (possibly corrupted), removing: %v", err)
		if time.Since(info.ModTime()) > 10*time.Minute {
			tryRemoveFile(cachePath)
		}
		return false
	}

	// 校验 digest 完整性
	if isDigestRequest(c.Request.URL.Path) {
		expectedDigest := extractDigestFromPath(c.Request.URL.Path)
		if expectedDigest != "" {
			hash := sha256.Sum256(cachedResp.Body)
			calculatedDigest := hex.EncodeToString(hash[:])
			if calculatedDigest != expectedDigest {
				log.Printf("WARNING cache file digest mismatch, removing: %s (expected: %s, got: %s)", cachePath, expectedDigest, calculatedDigest)
				if time.Since(info.ModTime()) > 10*time.Minute {
					tryRemoveFile(cachePath)
				}
				return false
			}
		}
	}

	// 设置响应头
	for k, v := range cachedResp.Headers {
		c.Header(k, v)
	}
	c.Header("X-Cache", "HIT")

	// 发送响应
	contentType := cachedResp.Headers["Content-Type"]
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	c.Data(cachedResp.StatusCode, contentType, cachedResp.Body)

	log.Printf("INFO cache HIT for %s", c.Request.URL.String())
	return true
}

// writeToCacheAsync 异步写入缓存（不阻塞响应返回）
func writeToCacheAsync(body []byte, headers map[string]string, statusCode int, path string) {
	if CacheDir == "" {
		return
	}

	// 只缓存 digest 文件（基于内容寻址，永久有效）
	if !isDigestRequest(path) {
		return
	}

	// 获取digest值作为文件名
	digest := extractDigestFromPath(path)
	if digest == "" {
		return
	}

	cachePath := getDigestCachePath(digest)
	markerPath := getDigestCacheMarkerPath(digest)

	// 检查缓存文件是否已存在且没有写入标记
	if _, err := os.Stat(cachePath); err == nil {
		// 检查是否有写入标记
		if writing, writeTime := isDigestCacheWriting(digest); writing {
			// 如果标记文件存在超过超时时间，认为之前的写入失败，清理后重新写入
			if time.Since(writeTime) > cacheWriteTimeout {
				log.Printf("WARNING previous cache write timeout, cleaning up: %s", cachePath)
				tryRemoveFile(cachePath)
				tryRemoveFile(markerPath)
			} else {
				// 正在写入中，跳过
				return
			}
		} else {
			// 文件已存在且没有写入标记，跳过写入
			return
		}
	}

	// 创建写入标记文件（隐藏文件，包含时间戳）
	timestamp := time.Now().UnixNano()
	markerData, err := json.Marshal(timestamp)
	if err != nil {
		log.Printf("WARNING failed to marshal marker: %v", err)
		return
	}

	// 创建目录
	cacheDir := filepath.Dir(cachePath)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Printf("WARNING failed to create cache directory: %v", err)
		return
	}

	// 先创建标记文件
	if err := os.WriteFile(markerPath, markerData, 0644); err != nil {
		log.Printf("WARNING failed to create cache marker: %v", err)
		return
	}

	// 准备缓存数据
	cachedResp := struct {
		StatusCode int               `json:"statusCode"`
		Headers    map[string]string `json:"headers"`
		Body       []byte            `json:"body"`
	}{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
	}

	// 序列化缓存数据
	data, err := json.Marshal(cachedResp)
	if err != nil {
		log.Printf("WARNING failed to marshal cache: %v", err)
		tryRemoveFile(markerPath) // 清理标记文件
		return
	}

	// 直接写入缓存文件
	file, err := os.OpenFile(cachePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("WARNING failed to create cache file: %v", err)
		tryRemoveFile(markerPath)
		return
	}

	// 写入数据到文件
	if _, err := file.Write(data); err != nil {
		log.Printf("WARNING failed to write cache file: %v", err)
		file.Close()
		tryRemoveFile(cachePath)
		tryRemoveFile(markerPath)
		return
	}

	// 同步到磁盘，确保数据完整性
	if err := file.Sync(); err != nil {
		log.Printf("WARNING failed to sync cache file: %v", err)
		file.Close()
		tryRemoveFile(cachePath)
		tryRemoveFile(markerPath)
		return
	}

	// 关闭文件
	if err := file.Close(); err != nil {
		log.Printf("WARNING failed to close cache file: %v", err)
		tryRemoveFile(markerPath)
		return
	}

	// 写入成功，删除标记文件
	if err := tryRemoveFile(markerPath); err != nil {
		log.Printf("WARNING failed to remove cache marker: %v", err)
	}

	debugLog("INFO cache MISS, saved to cache: %s", cachePath)
}

// tryRemoveFile 尝试删除文件，避免因文件不存在导致的错误日志
func tryRemoveFile(name string) error {
	err := os.Remove(name)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// writeToCache 将响应写入缓存（在 ModifyResponse 中调用，需要同步读取响应体）
func writeToCache(resp *http.Response) {
	// 只缓存 GET 请求且状态码为 200 的响应
	if resp.Request.Method != "GET" || resp.StatusCode != http.StatusOK {
		return
	}

	// 只缓存 digest 文件（基于内容寻址，永久有效）
	if !isDigestRequest(resp.Request.URL.Path) {
		return
	}

	// 读取响应体（必须在 ModifyResponse 中同步读取，因为需要恢复响应体）
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("WARNING failed to read response body for cache: %v", err)
		return
	}

	// 恢复响应体（因为已经被读取了）
	resp.Body = io.NopCloser(bytes.NewReader(body))

	// 复制响应头（只保存需要的）
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			// 跳过一些不应该缓存的头
			lowerKey := strings.ToLower(k)
			if lowerKey != "connection" && lowerKey != "transfer-encoding" {
				headers[k] = v[0]
			}
		}
	}

	// 异步写入缓存，不阻塞响应返回
	go writeToCacheAsync(body, headers, resp.StatusCode, resp.Request.URL.Path)
}

// forward handles proxy requests
func forward(c *gin.Context) {
	// 检查缓存（仅对 GET 请求）
	if c.Request.Method == "GET" && CacheDir != "" {
		cacheKey := getCacheKey(c.Request)
		if readFromCache(c, cacheKey) {
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
			defaultURL, err := url.Parse(RegistryMap["default"])
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
			} else if !strings.Contains(host, ".") {
				debugLog("INFO client %s request host is a hostname: %s", c.ClientIP(), c.Request.Host)
			} else {
				debugLog("INFO client %s coming through host %s", c.ClientIP(), c.Request.Host)
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
					log.Printf("ERROR failed to parse token URL: %v", err)
					req.URL.Scheme = "invalid"
					req.URL.Host = "invalid"
					return
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

			// 获取请求scheme
			reqScheme := "http"
			if c.Request.URL.Scheme != "" {
				reqScheme = c.Request.URL.Scheme
			} else if c.Request.TLS != nil {
				reqScheme = "https"
			}

			debugLog("INFO Proxying request: %s %s://%s%s -> %s://%s%s",
				c.Request.Method,
				reqScheme,
				c.Request.Host,
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

				debugLog("INFO modified Www-Authenticate header: %s => %s", wwwAuth, newWWWAuth)
			}

			// 写入缓存（同步读取响应体，异步写入文件）
			if CacheDir != "" {
				writeToCache(resp)
			}

			return nil
		},
		Transport: tr,
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

var version, buildTime string

func main() {
	var help bool
	var showVersion bool
	var listen string
	var registryMapSource string

	flag.StringVar(&listen, "listen", ":5000", "backend listen address")
	flag.StringVar(&DomainSuffix, "domain-suffix", "", "domain suffix for mirror hosts, e.g. mydomain.com; if empty use default registry as upstream")
	flag.StringVar(&registryMapSource, "registry-map", "", "registry map file path or URL (default: embed registrymap.json)")
	flag.StringVar(&CacheDir, "cache-dir", "", "local cache directory for caching responses (optional, disabled if empty)")
	flag.BoolVar(&help, "help", false, "show help")
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

	// 验证默认registry是否存在
	if RegistryMap["default"] == "" {
		log.Fatalf("ERROR no default registry found in registry map")
	}
	log.Printf("INFO registry-map: using default registry: %s", RegistryMap["default"])

	// 初始化缓存目录
	if CacheDir != "" {
		if err := os.MkdirAll(CacheDir, 0755); err != nil {
			log.Fatalf("ERROR failed to create cache directory %s: %v", CacheDir, err)
		}
		log.Printf("INFO cache: enabled, cache directory: %s", CacheDir)
	} else {
		log.Printf("INFO cache: disabled")
	}

	gin.SetMode(gin.ReleaseMode)

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

	log.Printf("INFO server: crproxy listening on %s, domain-suffix=%q", listen, DomainSuffix)
	log.Fatal(r.Run(listen))
}
