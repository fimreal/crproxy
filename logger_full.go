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

		// 排除不需要统计和记录日志的路径
		excludePaths := []string{"/healthz", "/admin", "/help", "/favicon.ico"}
		shouldSkip := false
		for _, excludePath := range excludePaths {
			if path == excludePath || strings.HasPrefix(path, excludePath+"/") {
				shouldSkip = true
				break
			}
		}

		// 只统计代理请求（/v2/ 和 /token/ 路径）
		isProxyRequest := strings.HasPrefix(path, "/v2/") || strings.HasPrefix(path, "/token/")

		// 增加活跃连接数（只统计代理请求）
		if statsCollector != nil && isProxyRequest && !shouldSkip {
			statsCollector.IncrementActiveConns()
			defer statsCollector.DecrementActiveConns()
		}

		// 处理请求
		c.Next()

		if shouldSkip {
			return
		}

		status := c.Writer.Status()
		size := c.Writer.Size()

		// 收集统计数据（所有代理请求，不管状态码）
		if statsCollector != nil && isProxyRequest {
			statsCollector.IncrementRequests()

			// 缓存统计（只统计成功的请求）
			if status >= 200 && status < 400 {
				switch c.Writer.Header().Get("X-Cache") {
				case "HIT":
					statsCollector.IncrementCacheHits()
				case "MISS":
					statsCollector.IncrementCacheMisses()
				}
			}

			// 客户端类型统计（所有请求）
			userAgent := c.GetHeader("User-Agent")
			clientType := parseClientType(userAgent)
			statsCollector.IncrementClient(clientType)

			// 上游统计（所有请求，从 gin.Context 获取）
			if upstreamHost, exists := c.Get("upstreamHost"); exists {
				statsCollector.IncrementUpstream(upstreamHost.(string))
			}

			// 镜像统计（所有请求）
			imageName := parseImageName(path)
			statsCollector.IncrementImage(imageName)

			// 客户端 IP 统计
			statsCollector.IncrementClientIP(c.ClientIP())

			// 流量统计（成功的请求）
			if status >= 200 && status < 400 && size > 0 {
				statsCollector.AddBytesWithRate(size)
			}
		}

		// 记录访问日志
		latency := time.Since(start)
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
