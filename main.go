package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

var DomainSuffix string
var DefaultUpstream string

// forward handles proxy requests
func forward(c *gin.Context) {
	// debug
	// for k, vals := range c.Request.Header {
	// 	log.Printf("Req Header: %s: %s ", k, strings.Join(vals, ","))
	// }

	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = DefaultUpstream
			req.Host = DefaultUpstream

			if strings.HasPrefix(req.URL.Path, "/token/") {
				upstream := req.URL.Path[len("/token/"):]
				u, err := url.Parse(upstream)
				if err != nil {
					log.Printf("proxy err url.Parse: %v", err)
					return
				}
				// 改过的 url 例如: http://127.0.0.1:5000/token/https://auth.docker.io/token?client_id=containerization-registry-client&service=registry.docker.io&scope=repository:library/alpine:pull
				// 需要修改为: https://auth.docker.io/token?client_id=containerization-registry-client&service=registry.docker.io&scope=repository:library/alpine:pull
				req.URL.Scheme = u.Scheme
				req.URL.Host = u.Host
				req.Host = u.Host
				req.URL.Path = u.Path
			}

			log.Printf("origin: %s %s %s", c.Request.Method, c.Request.Host, c.Request.URL.String())
			log.Printf("proxy: %s %s %s", req.URL.Scheme, req.URL.Host, req.URL.String())
		},
		ModifyResponse: func(resp *http.Response) error {
			reqScheme := c.Request.URL.Scheme
			reqHost := c.Request.Host

			if resp.StatusCode == http.StatusUnauthorized {
				log.Printf("proxy err httpcode: %d", resp.StatusCode)
				// log.Printf("proxy err req details: %s %s %s", c.Request.Method, c.Request.Host, c.Request.URL.String())
				for k, vals := range resp.Header {
					log.Printf("Resp Header: %s: %s\n", k, strings.Join(vals, ","))
				}
			}

			if wwwAuth := resp.Header.Get("Www-Authenticate"); wwwAuth != "" {

				realmURL, ok := getRealm(wwwAuth)
				if !ok {
					log.Printf("proxy err getRealmURL, Header Www-Authenticate: %v", wwwAuth)
					return fmt.Errorf("proxy err getRealmURL, Header Www-Authenticate: %v", wwwAuth)
				}

				if reqScheme == "" {
					reqScheme = "http"
				}
				proxyRealURL := fmt.Sprintf("%s://%s/token/%s", reqScheme, reqHost, realmURL)

				newWWWAuth := replaceRealm(wwwAuth, proxyRealURL)
				resp.Header.Set("Www-Authenticate", newWWWAuth)

				log.Printf("Got realm URL: %s", realmURL)
				log.Printf("modify resp header Www-Authenticate: %s", resp.Header.Get("Www-Authenticate"))

			}

			// for k, vals := range resp.Header {
			// 	log.Printf("Resp Header: %s: %s\n", k, strings.Join(vals, ","))
			// }
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

	flag.StringVar(&listen, "listen", ":5000", "backend listen address")
	// flag.StringVar(&DomainSuffix, "domain-suffix", "", "domain suffix for mirror hosts, e.g. mydomain.com; if empty use request host as upstream")
	flag.StringVar(&DefaultUpstream, "default-upstream", "registry-1.docker.io", "default registry upstream")
	flag.Parse()

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())

	r.Any("/v2/*path", forward)
	r.Any("/token/*path", forward)

	log.Printf("crproxy listening on %s [domain-suffix=%q default-upstream=%q]", listen, DomainSuffix, DefaultUpstream)
	log.Fatal(r.Run(listen))
}
