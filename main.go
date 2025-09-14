package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// RegistryMap 镜像仓库地址
var RegistryMap = map[string]string{
	"docker": "https://registry-1.docker.io",
	"gcr":    "https://gcr.io",
	"k8sgcr": "https://k8s.gcr.io",
	"k8s":    "https://registry.k8s.io",
	"quay":   "https://quay.io",
	"ghcr":   "https://ghcr.io",
}
var DefaultRegistry string
var DomainSuffix string

func findRegistryURL(host string) (*url.URL, error) {
	if DomainSuffix != "" && DomainSuffix != host && strings.HasSuffix(host, DomainSuffix) {
		registry := strings.TrimSuffix(host, "."+DomainSuffix)
		registryURL := RegistryMap[registry]
		if registryURL != "" {
			return url.Parse(registryURL)
		}
	}
	return nil, fmt.Errorf("registry not found")
}

// forward handles proxy requests
func forward(c *gin.Context) {
	// 预先检查registry是否存在（针对使用DomainSuffix的情况）
	if DomainSuffix != "" && strings.Contains(c.Request.Host, DomainSuffix) {
		_, err := findRegistryURL(c.Request.Host)
		if err != nil {
			log.Printf("ERROR registry not found for %s: %v", c.Request.Host, err)
			c.JSON(http.StatusNotFound, gin.H{
				"message": "registry not found: " + c.Request.Host + ", please check /help for available registries",
			})
			return
		}
	}

	// handel proxy request
	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// 初始化请求的基本信息, 默认使用默认registry
			defaultURL, _ := url.Parse(DefaultRegistry)
			req.URL.Scheme = defaultURL.Scheme
			req.URL.Host = defaultURL.Host
			req.Host = defaultURL.Host

			if !strings.Contains(c.Request.Host, ".") {
				log.Printf("WARNING client %s request host is a hostname: %s", c.ClientIP(), c.Request.Host)
			} else if host, _, err := net.SplitHostPort(c.Request.Host); err == nil && net.ParseIP(host) != nil {
				log.Printf("WARNING client %s request host is IP address %s, use default upstream: %s", c.ClientIP(), c.Request.Host, DefaultRegistry)
			} else if net.ParseIP(host) != nil {
				log.Printf("WARNING client %s request host is IP address %s, use default upstream: %s", c.ClientIP(), c.Request.Host, DefaultRegistry)
			} else {
				log.Printf("DEBUG client %s coming through host %s", c.ClientIP(), c.Request.Host)
				u, err := findRegistryURL(c.Request.Host)
				if err != nil {
					log.Printf("DEBUG registry not found for %s, using default: %s", c.Request.Host, DefaultRegistry)
				}

				req.URL.Scheme = u.Scheme
				req.URL.Host = u.Host
				req.Host = u.Host
			}

			// 处理 token
			if strings.HasPrefix(req.URL.Path, "/token/") {
				upstream := req.URL.Path[len("/token/"):]
				u, err := url.Parse(upstream)
				if err != nil {
					log.Printf("ERROR proxy err url.Parse: %v", err)
					return
				}
				// 改过的 url 例如: http://127.0.0.1:5000/token/https://auth.docker.io/token?client_id=containerization-registry-client&service=registry.docker.io&scope=repository:library/alpine:pull
				// 需要修改为: https://auth.docker.io/token?client_id=containerization-registry-client&service=registry.docker.io&scope=repository:library/alpine:pull
				req.URL.Scheme = u.Scheme
				req.URL.Host = u.Host
				req.Host = u.Host
				req.URL.Path = u.Path
			}

			log.Printf("INFO origin: %s %s %s", c.Request.Method, c.Request.Host, c.Request.URL.String())
			log.Printf("INFO proxy: %s %s %s", req.URL.Scheme, req.URL.Host, req.URL.String())
		},
		ModifyResponse: func(resp *http.Response) error {
			// 匿名请求遇到 401 时
			if resp.StatusCode == http.StatusUnauthorized {
				log.Printf("ERROR proxy err, httpcode: %d", resp.StatusCode)
				for k, vals := range resp.Header {
					log.Printf("DEBUG Resp Header: %s: %s\n", k, strings.Join(vals, ","))
				}
			}

			// 处理 token
			if wwwAuth := resp.Header.Get("Www-Authenticate"); wwwAuth != "" {
				realmURL, ok := getRealm(wwwAuth)
				if !ok {
					log.Printf("ERROR proxy err: getRealmURL: Header Www-Authenticate: %v", wwwAuth)
					return fmt.Errorf("proxy err: getRealmURL: Header Www-Authenticate: %v", wwwAuth)
				}

				// 修改 realm 地址到本服务
				reqScheme := c.Request.URL.Scheme
				if reqScheme == "" {
					reqScheme = "http"
				}
				reqHost := c.Request.Host
				// 把原始 realm 地址拼接到 /token/ 后
				proxyRealURL := fmt.Sprintf("%s://%s/token/%s", reqScheme, reqHost, realmURL)

				newWWWAuth := replaceRealm(wwwAuth, proxyRealURL)
				resp.Header.Set("Www-Authenticate", newWWWAuth)

				log.Printf("INFO modify resp header Www-Authenticate: %s => %s", wwwAuth, resp.Header.Get("Www-Authenticate"))
			}

			// 非 token 请求默认代理响应
			return nil
		},
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

func main() {
	var listen string
	var help bool

	flag.StringVar(&listen, "listen", ":5000", "backend listen address")
	flag.StringVar(&DomainSuffix, "domain-suffix", "", "domain suffix for mirror hosts, e.g. mydomain.com; if empty use default registry as upstream")
	flag.StringVar(&DefaultRegistry, "default-registry", RegistryMap["docker"], "default registry as upstream")
	flag.BoolVar(&help, "help", false, "show help")
	flag.Parse()

	if help {
		flag.Usage()
		return
	}

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())

	r.Any("/v2/*path", forward)
	r.Any("/token/*path", forward)

	r.GET("/help", func(c *gin.Context) {
		log.Printf("client %s request help information", c.ClientIP())
		c.JSON(200, RegistryMap)
	})
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	log.Printf("crproxy listening on %s [domain-suffix=%q default-upstream=%q]", listen, DomainSuffix, DefaultRegistry)
	log.Fatal(r.Run(listen))
}
