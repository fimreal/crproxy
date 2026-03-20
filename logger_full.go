//go:build !lite
// +build !lite

package main

import (
	"log/slog"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// accessLogMiddleware 访问日志中间件（完整版，带统计）
func accessLogMiddleware(statsCollector *StatsCollector) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		// 处理请求
		c.Next()

		// 排除不需要统计和记录日志的路径
		excludePaths := []string{"/healthz", "/admin", "/help", "/favicon.ico"}
		shouldSkip := false
		for _, excludePath := range excludePaths {
			if path == excludePath || strings.HasPrefix(path, excludePath+"/") {
				shouldSkip = true
				break
			}
		}

		if shouldSkip {
			return
		}

		// 只统计代理请求（/v2/ 和 /token/ 路径）
		isProxyRequest := strings.HasPrefix(path, "/v2/") || strings.HasPrefix(path, "/token/")
		status := c.Writer.Status()

		// 收集统计数据（只统计成功的代理请求）
		if statsCollector != nil && isProxyRequest && status >= 200 && status < 400 {
			statsCollector.IncrementRequests()
			switch c.Writer.Header().Get("X-Cache") {
			case "HIT":
				statsCollector.IncrementCacheHits()
			case "MISS":
				statsCollector.IncrementCacheMisses()
			}
		}

		// 记录访问日志
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
