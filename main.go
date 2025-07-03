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

var version = "unknown"
var buildTime = ""

// tokenCacheEntry is used to cache token and its expiration time
var tokenCache sync.Map // key: service|scope, value: tokenCacheEntry

type tokenCacheEntry struct {
	token      string
	expireTime time.Time
}

// handleProxyRequest handles all /v2/* requests and proxies them to the appropriate upstream registry.
func handleProxyRequest(c *gin.Context) {
	// Health check for /v2 and /v2/
	if c.Request.URL.Path == "/v2" || c.Request.URL.Path == "/v2/" {
		c.Status(http.StatusOK)
		return
	}

	path := c.Request.URL.Path
	ezap.Debugf("Request Got: client=%s path=%s", c.ClientIP(), path)

	// Parse /v2/{prefix}/{repoPath}
	trimmed := strings.TrimPrefix(path, "/v2/")
	splitIdx := strings.Index(trimmed, "/")
	if splitIdx == -1 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid path: missing image name after /v2/",
			"path":    path,
		})
		return
	}
	registry := trimmed[:splitIdx]
	repoPath := trimmed[splitIdx+1:]
	if registry == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message":  "invalid path: missing registry prefix after /v2/",
			"path":     path,
			"registry": "",
		})
		return
	}

	// Special case for docker.io
	upstream := "https://" + registry
	if registry == "docker.io" {
		upstream = "https://registry-1.docker.io"
		// Accurately extract repo name by finding the last resource keyword
		resourceKeywords := []string{"/manifests/", "/blobs/", "/tags/", "/uploads/", "/mount/"}
		repoName := repoPath
		maxIdx := -1
		for _, kw := range resourceKeywords {
			if idx := strings.LastIndex(repoPath, kw); idx != -1 && idx > maxIdx {
				maxIdx = idx
			}
		}
		if maxIdx != -1 {
			repoName = repoPath[:maxIdx]
		}
		// Only add 'library/' if repoName is single-segment
		if !strings.Contains(repoName, "/") {
			ezap.Info("repoPath: ", repoName)
			repoPath = "library/" + repoPath
		}
	}

	// Build upstream URL
	newURL := upstream + "/v2/" + repoPath
	if c.Request.URL.RawQuery != "" {
		newURL += "?" + c.Request.URL.RawQuery
	}

	if strings.Contains(path, "/blobs/") {
		digest := ""
		if parts := strings.SplitN(path, "/blobs/", 2); len(parts) == 2 {
			digest = parts[1]
		}
		ezap.Infof("Proxy blob: client=%s registry=%s repoPath=%s digest=%s", c.ClientIP(), registry, repoPath, digest)
	} else {
		ezap.Infof("Proxy image: client=%s method=%s registry=%s repoPath=%s", c.ClientIP(), c.Request.Method, registry, repoPath)
	}

	var resp *http.Response
	var err error

	isBlobRequest := strings.Contains(path, "/blobs/")
	if isBlobRequest {
		// Try to use token cache for blob requests to avoid an extra 401 round-trip.
		service := registry
		scope := "repository:" + repoPath[:strings.Index(repoPath, "/")] + ":pull"
		// Support multi-level repo path
		if slashIdx := strings.LastIndex(repoPath, "/"); slashIdx != -1 {
			scope = "repository:" + repoPath[:slashIdx] + ":pull"
		}
		cacheKey := service + "|" + scope
		if v, ok := tokenCache.Load(cacheKey); ok {
			entry := v.(tokenCacheEntry)
			if entry.expireTime.After(time.Now().Add(10 * time.Second)) {
				// Cache hit, send request with Bearer token
				req, _ := http.NewRequest(c.Request.Method, newURL, c.Request.Body)
				for key, values := range c.Request.Header {
					for _, value := range values {
						req.Header.Add(key, value)
					}
				}
				req.Host = req.URL.Host
				req.Header.Set("Authorization", "Bearer "+entry.token)
				resp, err = http.DefaultClient.Do(req)
				// If token is expired/invalid, fallback to normal auth flow
				if err != nil || (resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403)) {
					if resp != nil {
						resp.Body.Close()
					}
					resp = nil
				}
			}
		}
	}
	if resp == nil {
		resp, err = forwardWithAuthRetry(newURL, c.Request)
	}
	if err != nil {
		ezap.Errorf("Proxy error: %v", err)
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	// Always close the upstream response body to avoid resource leaks.
	defer resp.Body.Close()

	ezap.Debugf("Upstream response: %s", resp.Status)

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

	// (need comment)
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
	var showVersion bool

	flag.StringVar(&port, "port", os.Getenv("PORT"), "listen port")
	flag.BoolVar(&debug, "debug", false, "debug mode")
	flag.BoolVar(&showVersion, "version", false, "show version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("crproxy version: %s\nbuild time: %s\n", version, buildTime)
		return
	}

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
