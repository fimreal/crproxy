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

var version, buildTime string

const (
	// cacheWriteTimeout 缓存写入超时时间（5分钟，适合大文件）
	cacheWriteTimeout = 5 * time.Minute
)

//go:embed registrymap.json
var embedRegistryMap []byte

// RegistryMap 镜像仓库地址
var RegistryMap map[string]string

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

// redirectTransport 包装 Transport 以支持在代理内部处理重定向
type redirectTransport struct {
	transport http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 先执行原始请求
	resp, err := rt.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// 如果是重定向响应（301, 302, 307, 308），且重定向到不同域名，则在内部跟随
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			redirectURL, err := url.Parse(location)
			if err != nil {
				return resp, nil // 返回原始响应，让客户端处理
			}

			// 如果重定向到不同的域名，在代理内部跟随重定向
			if redirectURL.Host != req.URL.Host {
				debugLog("DEBUG following redirect: %s -> %s", req.URL.Host, redirectURL.Host)

				// 关闭原始响应体
				resp.Body.Close()

				// 创建新的重定向请求（不能使用 req.Clone，因为会复制 RequestURI）
				redirectReq, err := http.NewRequest(req.Method, location, nil)
				if err != nil {
					log.Printf("ERROR failed to create redirect request: %v", err)
					return resp, nil // 返回原始响应
				}

				// 复制原始请求的头部（除了 Host）
				for k, v := range req.Header {
					// 跳过一些不应该复制的头部
					lowerKey := strings.ToLower(k)
					if lowerKey != "host" && lowerKey != "connection" {
						redirectReq.Header[k] = v
					}
				}

				// 设置 Host header
				redirectReq.Host = redirectURL.Host

				// 跟随重定向（使用相同的 Transport）
				redirectResp, err := rt.transport.RoundTrip(redirectReq)
				if err != nil {
					log.Printf("ERROR failed to follow redirect: %v", err)
					return resp, nil // 返回原始响应
				}

				return redirectResp, nil
			}
		}
	}

	return resp, nil
}

// isBlobRequest 检查是否是 blob 请求（只缓存 blobs，不缓存 manifests）
func isBlobRequest(path string) bool {
	// 只缓存 blobs（镜像层），不缓存 manifests（清单文件会更新）
	return strings.Contains(path, "/blobs/sha256:") ||
		strings.Contains(path, "/blobs/sha512:")
}

// extractDigestFromPath 从路径中提取 digest 值
func extractDigestFromPath(path string) string {
	// 提取 sha256:<digest> 或 sha512:<digest>
	for _, prefix := range []string{"sha256:", "sha512:"} {
		idx := strings.Index(path, prefix)
		if idx != -1 {
			digest := path[idx+len(prefix):]
			// 去掉可能的查询参数和路径分隔符
			digest = strings.Split(digest, "?")[0]
			digest = strings.Split(digest, "/")[0]
			return digest
		}
	}
	return ""
}

// getCachePath 根据 digest 获取缓存文件路径
func getCachePath(digest string) string {
	// 使用前两个字符作为子目录，避免单个目录文件过多
	if len(digest) < 2 {
		return filepath.Join(CacheDir, digest)
	}
	subDir := digest[:2]
	return filepath.Join(CacheDir, subDir, digest)
}

// readFromCache 从缓存读取响应
func readFromCache(c *gin.Context) bool {
	if CacheDir == "" {
		return false
	}

	// 只缓存 blobs
	if !isBlobRequest(c.Request.URL.Path) {
		return false
	}

	digest := extractDigestFromPath(c.Request.URL.Path)
	if digest == "" {
		return false
	}

	cachePath := getCachePath(digest)

	// 检查缓存文件是否存在
	_, err := os.Stat(cachePath)
	if err != nil {
		return false
	}

	// 检查临时文件（正在写入中）
	tmpPath := cachePath + ".tmp"
	if tmpInfo, err := os.Stat(tmpPath); err == nil {
		// 如果临时文件存在超过超时时间，清理它
		if time.Since(tmpInfo.ModTime()) > cacheWriteTimeout {
			tryRemoveFile(tmpPath)
		} else {
			// 正在写入中，跳过缓存
			return false
		}
	}

	// 读取缓存文件
	data, err := os.ReadFile(cachePath)
	if err != nil {
		log.Printf("WARNING failed to read cache file: %v", err)
		return false
	}

	if len(data) == 0 {
		tryRemoveFile(cachePath)
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
		tryRemoveFile(cachePath)
		return false
	}

	// 校验 digest 完整性
	hash := sha256.Sum256(cachedResp.Body)
	calculatedDigest := hex.EncodeToString(hash[:])
	if calculatedDigest != digest {
		log.Printf("WARNING cache file digest mismatch, removing: %s (expected: %s, got: %s)", cachePath, digest, calculatedDigest)
		tryRemoveFile(cachePath)
		return false
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

	debugLog("DEBUG cache HIT: %s", c.Request.URL.Path)
	return true
}

// writeToCacheAsync 异步写入缓存（不阻塞响应返回）
func writeToCacheAsync(body []byte, headers map[string]string, statusCode int, path string) {
	if CacheDir == "" {
		return
	}

	// 只缓存 blobs
	if !isBlobRequest(path) {
		return
	}

	digest := extractDigestFromPath(path)
	if digest == "" {
		return
	}

	cachePath := getCachePath(digest)
	tmpPath := cachePath + ".tmp"

	// 检查缓存文件是否已存在
	if _, err := os.Stat(cachePath); err == nil {
		// 文件已存在，跳过写入
		return
	}

	// 检查临时文件（可能正在写入中）
	if tmpInfo, err := os.Stat(tmpPath); err == nil {
		// 如果临时文件存在超过超时时间，清理它
		if time.Since(tmpInfo.ModTime()) > cacheWriteTimeout {
			tryRemoveFile(tmpPath)
		} else {
			// 正在写入中，跳过
			return
		}
	}

	// 创建目录
	cacheDir := filepath.Dir(cachePath)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Printf("WARNING failed to create cache directory: %v", err)
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
		return
	}

	// 原子写入：先写入临时文件，然后重命名
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		log.Printf("WARNING failed to write cache file: %v", err)
		tryRemoveFile(tmpPath)
		return
	}

	// 原子重命名（在大多数文件系统上是原子操作）
	if err := os.Rename(tmpPath, cachePath); err != nil {
		log.Printf("WARNING failed to rename cache file: %v", err)
		tryRemoveFile(tmpPath)
		return
	}

	debugLog("DEBUG cache MISS, saved: %s", cachePath)
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

	// 只缓存 blobs
	if !isBlobRequest(resp.Request.URL.Path) {
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

	// 初始化缓存目录
	if CacheDir != "" {
		if err := os.MkdirAll(CacheDir, 0755); err != nil {
			log.Fatalf("ERROR failed to create cache directory %s: %v", CacheDir, err)
		}
		log.Printf("INFO cache: enabled, cache directory: %s", CacheDir)
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

	log.Printf("INFO server: crproxy listening on %s, domain-suffix=%q", listen, DomainSuffix)
	log.Fatal(r.Run(listen))
}
