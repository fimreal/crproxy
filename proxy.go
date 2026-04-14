package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// maxRedirects 最大重定向次数
	maxRedirects = 10
)

var tr = &http.Transport{
	MaxIdleConns:          100,
	IdleConnTimeout:       30 * time.Second,
	MaxIdleConnsPerHost:   10,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
	Proxy:                 http.ProxyFromEnvironment,
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
				// 只有在启用 DomainSuffix 模式时，才做基于域名的 registry 路由查找。
				// 单上游模式（DomainSuffix == ""）直接使用默认 upstream，避免无意义的告警日志。
				if DomainSuffix != "" {
					u, err := findRegistryURL(c.Request.Host)
					if err != nil {
						slog.Warn("registry not found, using default", "host", c.Request.Host, "default", registryMap["default"])
					} else {
						req.URL.Scheme = u.Scheme
						req.URL.Host = u.Host
						req.Host = u.Host
					}
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

			debugLog("proxy request",
				"method", c.Request.Method,
				"from", c.Request.URL.RequestURI(),
				"to", fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.URL.Host, req.URL.RequestURI()))
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
				// 优先检查反向代理传递的 X-Forwarded-Proto 头部
				reqScheme := c.GetHeader("X-Forwarded-Proto")
				if reqScheme == "" {
					// 如果没有 X-Forwarded-Proto，检查是否为 TLS 连接
					if c.Request.TLS != nil {
						reqScheme = "https"
					} else {
						reqScheme = "http"
					}
				}
				reqHost := c.Request.Host
				// 如果反向代理设置了 X-Forwarded-Host，使用它
				if fwdHost := c.GetHeader("X-Forwarded-Host"); fwdHost != "" {
					reqHost = fwdHost
				}
				// 把原始 realm 地址拼接到 /token/ 后
				proxyRealURL := fmt.Sprintf("%s://%s/token/%s", reqScheme, reqHost, realmURL)

				newWWWAuth := replaceRealm(wwwAuth, proxyRealURL)
				resp.Header.Set("Www-Authenticate", newWWWAuth)

				debugLog("modified Www-Authenticate", "value", newWWWAuth)
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
