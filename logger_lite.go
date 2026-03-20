//go:build lite
// +build lite

package main

import (
	"log/slog"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// accessLogMiddleware 访问日志中间件（轻量版，无统计）
func accessLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		// 处理请求
		c.Next()

		// 排除不需要记录日志的路径
		excludePaths := []string{"/healthz", "/favicon.ico"}
		for _, excludePath := range excludePaths {
			if path == excludePath || strings.HasPrefix(path, excludePath+"/") {
				return
			}
		}

		// 记录访问日志
		status := c.Writer.Status()
		latency := time.Since(start)
		size := c.Writer.Size()
		requestID, _ := c.Get("requestID")
		cacheStatus := c.Writer.Header().Get("X-Cache")
		if cacheStatus == "" {
			cacheStatus = "BYPASS"
		}

		slog.Info("request",
			"request_id", requestID,
			"method", c.Request.Method,
			"path", path,
			"query", query,
			"status", status,
			"latency_ms", latency.Milliseconds(),
			"size", size,
			"client_ip", c.ClientIP(),
			"cache", cacheStatus,
		)
	}
}
