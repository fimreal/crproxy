package main

import (
	_ "embed"
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
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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
		} else {
			// 从本地文件加载
			data, err = os.ReadFile(source)
			if err != nil {
				return nil, fmt.Errorf("ERROR failed to read registry map file %s: %v", source, err)
			}
			log.Printf("INFO registry-map: loaded registry map from file: %s", source)
		}
		if resp != nil {
			data, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("ERROR failed to read response body: %v", err)
			}
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
		for _, v := range registryMap {
			if v != "" {
				registryMap["default"] = v
				break
			}
		}
	}

	log.Printf("DEBUG registry-map: available registries: %v", registryMap)
	return registryMap, nil
}

var DomainSuffix string

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

// forward handles proxy requests
func forward(c *gin.Context) {
	// 预先检查registry是否存在（针对使用DomainSuffix的情况）
	if DomainSuffix != "" && strings.Contains(c.Request.Host, DomainSuffix) {
		_, err := findRegistryURL(c.Request.Host)
		if err != nil {
			log.Printf("ERROR registry not found desc=\"%v\"", err)
			c.JSON(http.StatusNotFound, gin.H{
				"message": "registry not found: " + c.Request.Host + ", please visit /help for available registries",
			})
			return
		}
	}

	// handel proxy request
	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// 初始化请求的基本信息, 默认使用默认registry
			defaultURL, _ := url.Parse(RegistryMap["default"])
			req.URL.Scheme = defaultURL.Scheme
			req.URL.Host = defaultURL.Host
			req.Host = defaultURL.Host

			if !strings.Contains(c.Request.Host, ".") {
				log.Printf("WARNING client %s request host is a hostname: %s", c.ClientIP(), c.Request.Host)
			} else if host, _, err := net.SplitHostPort(c.Request.Host); err == nil && net.ParseIP(host) != nil {
				log.Printf("WARNING client %s request host is IP address %s, use default upstream: %s", c.ClientIP(), c.Request.Host, RegistryMap["default"])
			} else if net.ParseIP(host) != nil {
				log.Printf("WARNING client %s request host is IP address %s, use default upstream: %s", c.ClientIP(), c.Request.Host, RegistryMap["default"])
			} else {
				log.Printf("INFO client %s coming through host %s", c.ClientIP(), c.Request.Host)
				u, err := findRegistryURL(c.Request.Host)
				if err != nil {
					log.Printf("WARNING registry not found for %s, using default: %s", c.Request.Host, RegistryMap["default"])
				} else {
					req.URL.Scheme = u.Scheme
					req.URL.Host = u.Host
					req.Host = u.Host
				}
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

			log.Printf("INFO Proxying request: %s %s://%s%s -> %s://%s%s",
				c.Request.Method,
				func() string {
					if c.Request.URL.Scheme != "" {
						return c.Request.URL.Scheme
					} else {
						return "http"
					}
				}(),
				c.Request.Host,
				c.Request.URL.RequestURI(),
				req.URL.Scheme,
				req.URL.Host,
				req.URL.RequestURI())
		},
		ModifyResponse: func(resp *http.Response) error {
			// 匿名请求遇到 401 时
			if resp.StatusCode == http.StatusUnauthorized {
				log.Printf("ERROR proxy err, httpcode: %d %s", resp.StatusCode, resp.Request.URL.String())
				// for k, vals := range resp.Header {
				// 	log.Printf("DEBUG Resp Header: %s: %s\n", k, strings.Join(vals, ","))
				// }
			}

			// 处理 token
			if wwwAuth := resp.Header.Get("Www-Authenticate"); wwwAuth != "" {
				realmURL, ok := getRealm(wwwAuth)
				if !ok {
					log.Printf("ERROR proxy err: getRealmURL: Header Www-Authenticate: %v", wwwAuth)
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

				log.Printf("INFO modify resp header Www-Authenticate: %s => %s", wwwAuth, resp.Header.Get("Www-Authenticate"))
			}

			// 非 token 请求默认代理响应
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
	log.Printf("INFO registry-map: using default registry: %s", RegistryMap["default"])

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())

	r.Any("/v2/*path", forward)
	r.Any("/token/*path", forward)

	r.GET("/help", func(c *gin.Context) {
		log.Printf("INFO client %s request help information", c.ClientIP())
		c.JSON(200, RegistryMap)
	})
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	log.Printf("INFO server: crproxy listening on %s, domain-suffix=%q", listen, DomainSuffix)
	log.Fatal(r.Run(listen))
}
