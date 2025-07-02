package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fimreal/goutils/ezap"
	"github.com/gin-gonic/gin"
)

// tokenCacheEntry 用于缓存 token 及其过期时间
var tokenCache sync.Map // key: service|scope, value: tokenCacheEntry

type tokenCacheEntry struct {
	token      string
	expireTime time.Time
}

// handleProxyRequest handles all /v2/* requests and proxies them to the appropriate upstream registry.
func handleProxyRequest(c *gin.Context) {
	path := c.Request.URL.Path

	// Docker registry API requires /v2/ to return 200 OK for health check
	if path == "/v2/" || path == "/v2" {
		c.Status(http.StatusOK)
		return
	}

	// Parse /v2/{prefix}/...
	parts := strings.SplitN(strings.TrimPrefix(path, "/v2/"), "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		c.JSON(http.StatusNotFound, gin.H{"message": "error: not found"})
		return
	}
	prefix := parts[0]

	// Special case for docker.io
	upstream := "https://" + prefix
	if prefix == "docker.io" {
		upstream = "https://registry-1.docker.io"
		// auto add library/ if not present
		if len(parts) > 1 && (parts[1] == "" || !strings.HasPrefix(parts[1], "library/")) {
			parts[1] = "library/" + parts[1]
		}
	}

	rest := ""
	if len(parts) == 2 {
		rest = parts[1]
	}

	// Build upstream URL
	newURL := upstream + "/v2/" + rest
	if c.Request.URL.RawQuery != "" {
		newURL += "?" + c.Request.URL.RawQuery
	}

	// info 日志：只保留这条
	ezap.Infof("Proxy image: client=%s method=%s path=%s upstream=%s", c.ClientIP(), c.Request.Method, path, newURL)

	// 如果是 blob 下载，额外输出一条 info 日志
	if strings.Contains(path, "/blobs/") {
		digest := ""
		idx := strings.Index(path, "/blobs/")
		if idx != -1 {
			digest = path[idx+len("/blobs/"):]
		}
		ezap.Infof("Proxy blob: client=%s repo=%s digest=%s upstream=%s", c.ClientIP(), prefix, digest, newURL)
	}

	resp, err := forwardWithAuthRetry(newURL, c.Request)
	if err != nil {
		ezap.Errorf("Proxy error: %v", err)
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	defer resp.Body.Close()

	// debug 日志：只保留关键流程
	ezap.Debugf("Upstream response: %d %s", resp.StatusCode, resp.Status)

	copyResponse(c, resp)
}

// forwardWithAuthRetry forwards the request to the upstream registry.
// If a 401 with Bearer challenge is received, it tries to exchange Basic for Bearer token and retries.
func forwardWithAuthRetry(url string, originalReq *http.Request) (*http.Response, error) {
	req, err := http.NewRequest(originalReq.Method, url, originalReq.Body)
	if err != nil {
		return nil, err
	}
	for key, values := range originalReq.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	req.Host = req.URL.Host

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		authHeader := resp.Header.Get("Www-Authenticate")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			ezap.Debugf("Received 401, attempting token exchange")
			authParams := parseBearerAuthHeader(authHeader)
			realm := authParams["realm"]
			service := authParams["service"]
			scope := authParams["scope"]
			basicAuth := originalReq.Header.Get("Authorization")
			token, tokenErr := getBearerToken(realm, service, scope, basicAuth)
			if tokenErr != nil {
				ezap.Errorf("Failed to get bearer token: %v", tokenErr)
				return resp, nil // Return original 401
			}
			resp.Body.Close()
			// Retry with Bearer token
			req2, err2 := http.NewRequest(originalReq.Method, url, originalReq.Body)
			if err2 != nil {
				return nil, err2
			}
			for key, values := range originalReq.Header {
				for _, value := range values {
					req2.Header.Add(key, value)
				}
			}
			req2.Host = req.URL.Host
			req2.Header.Set("Authorization", "Bearer "+token)
			ezap.Debugf("Got bearer token, retrying with Bearer token")
			return http.DefaultClient.Do(req2)
		}
	}
	return resp, nil
}

// parseBearerAuthHeader parses the WWW-Authenticate Bearer header into a map.
func parseBearerAuthHeader(header string) map[string]string {
	result := make(map[string]string)
	parts := strings.Split(strings.TrimPrefix(header, "Bearer "), ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			result[kv[0]] = strings.Trim(kv[1], `"`)
		}
	}
	return result
}

// getBearerToken exchanges Basic auth for a Bearer token from the auth server, with cache.
func getBearerToken(realm, service, scope, basicAuth string) (string, error) {
	key := service + "|" + scope
	if v, ok := tokenCache.Load(key); ok {
		entry := v.(tokenCacheEntry)
		if entry.expireTime.After(time.Now().Add(10 * time.Second)) {
			ezap.Debugf("Token cache hit for key=%s", key)
			return entry.token, nil
		}
		ezap.Debugf("Token cache expired for key=%s", key)
	} else {
		ezap.Debugf("Token cache miss for key=%s", key)
	}

	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := tokenURL.Query()
	if service != "" {
		q.Set("service", service)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	tokenURL.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", tokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	if basicAuth != "" {
		req.Header.Set("Authorization", basicAuth)
	}
	ezap.Debugf("Requesting bearer token from: %s", tokenURL.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var respData struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		IssuedAt    string `json:"issued_at"`
	}
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &respData)
	var token string
	if respData.Token != "" {
		token = respData.Token
		ezap.Debugf("Got bearer token")
	} else if respData.AccessToken != "" {
		token = respData.AccessToken
		ezap.Debugf("Got access token")
	} else {
		ezap.Errorf("No token in response: %s", string(body))
		return "", fmt.Errorf("no token in response: %s", string(body))
	}
	// 计算过期时间
	expire := time.Now().Add(300 * time.Second) // 默认5分钟
	if respData.ExpiresIn > 0 {
		expire = time.Now().Add(time.Duration(respData.ExpiresIn) * time.Second)
	}
	// 存入缓存
	tokenCache.Store(key, tokenCacheEntry{token: token, expireTime: expire})
	return token, nil
}

// copyResponse copies the upstream response to the client.
func copyResponse(c *gin.Context, resp *http.Response) {
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}
	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}

func main() {
	var port string
	var debug bool

	flag.StringVar(&port, "port", os.Getenv("PORT"), "listen port")
	flag.BoolVar(&debug, "debug", false, "debug mode")
	flag.Parse()

	if port == "" {
		port = "5000"
	}

	if debug {
		gin.SetMode(gin.DebugMode)
		ezap.SetLevel("debug")
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()

	r.Any("/v2/*path", handleProxyRequest)

	ezap.Infof("container registry proxy server listen on : :%s", port)
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		if v := os.Getenv(key); v != "" {
			ezap.Infof("%s=%s", key, v)
		}
	}
	ezap.Error(r.Run(":" + port))
}
