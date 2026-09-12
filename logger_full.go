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

		// 登记实时任务并统计活跃连接（只统计代理请求）
		track := statsCollector != nil && isProxyRequest && !shouldSkip
		if track {
			live.Begin(c)
			statsCollector.IncrementActiveConns()
		}

		// 清理必须放在 defer 里：下游 handler 若 panic，c.Next() 之后的语句
		// 不会执行（panic 由更外层的 gin.Recovery 兜住），不 defer 的话活跃
		// 连接数会只增不减，实时任务也会永久滞留在 active 表中。
		// live.Finish 是幂等的，正常路径先调用，defer 只做兜底。
		cleaned := false
		cleanup := func() {
			if cleaned || !track {
				return
			}
			cleaned = true
			statsCollector.DecrementActiveConns()
			live.Finish(c, c.Writer.Status())
		}
		defer cleanup()

		// 处理请求
		c.Next()

		if shouldSkip {
			return
		}

		status := c.Writer.Status()
		size := c.Writer.Size()

		// 收集统计数据（所有代理请求，不管状态码）
		if track {
			// 先结算实时任务，再从上下文取回本次传输的实测字节数
			cleanup()
			task := liveTaskOf(c)
			cacheStatus := cacheStateOf(c)
			if task != nil && task.size() > 0 {
				size = int(task.size())
			}

			statsCollector.IncrementRequests()

			// 缓存统计（只统计成功的请求）
			if status >= 200 && status < 400 {
				switch cacheStatus {
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
				statsCollector.AddBytesSent(size)

				// 接收流量统计：优先用真正从上游读到的字节数，
				// 缓存命中的请求读到的上游字节为 0，天然不会计入。
				if recv := taskRecvBytes(task); recv > 0 {
					statsCollector.AddBytesReceived(int(recv))
				} else if cacheStatus != "HIT" {
					statsCollector.AddBytesReceived(size)
				}

				// 按客户端类型和 IP 统计流量
				statsCollector.AddClientBytes(clientType, size)
				statsCollector.AddClientIPBytes(c.ClientIP(), size)
			}
		}

		// 记录访问日志
		latency := time.Since(start)
		requestID, _ := c.Get("requestID")
		cacheStatus := cacheStateOf(c)

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

// taskRecvBytes 安全地读取任务的上游接收字节数。
func taskRecvBytes(task *liveTask) int64 {
	if task == nil {
		return 0
	}
	return task.recvBytes()
}
