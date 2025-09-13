// package handle

// import (
// 	"net/http"
// 	"strings"

// 	"github.com/fimreal/goutils/ezap"
// 	"github.com/gin-gonic/gin"
// )

// // ProxyRegistry handles all /v2/* requests and proxies them to the appropriate upstream registry.
// func ProxyRegistry(c *gin.Context) {
// 	// Health check for /v2 and /v2/
// 	if c.Request.URL.Path == "/v2" || c.Request.URL.Path == "/v2/" {
// 		c.Status(http.StatusOK)
// 		return
// 	}

// 	// test
// 	registry := "registry-1.docker.io"

// 	c.Request.Host = registry
// 	path := c.Request.URL.Path

// 	var resp *http.Response
// 	var err error

// 	if strings.Contains(path, "/blobs/") {
// 		req, _ := http.NewRequest(c.Request.Method, c.Request.RequestURI, c.Request.Body)
// 		for key, values := range c.Request.Header {
// 			for _, value := range values {
// 				req.Header.Add(key, value)
// 			}
// 		}
// 		req.Host = req.URL.Host
// 		req.Header.Set("Authorization", "Bearer "+entry.token)
// 		resp, err = http.DefaultClient.Do(req)
// 		// If token is expired/invalid, fallback to normal auth flow
// 		if err != nil || (resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403)) {
// 			if resp != nil {
// 				resp.Body.Close()
// 			}
// 			resp = nil
// 		}

// 	}
// 	if resp == nil {
// 		resp, err = forwardWithAuthRetry(newURL, c.Request)
// 	}
// 	if err != nil {
// 		ezap.Errorf("Proxy error: %v", err)
// 		c.String(http.StatusInternalServerError, err.Error())
// 		return
// 	}
// 	// Always close the upstream response body to avoid resource leaks.
// 	defer resp.Body.Close()

// 	ezap.Debugf("Upstream response: %s", resp.Status)

// 	copyResponse(c, resp)
// }
