package main

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 日志级别
var logLevel = new(slog.LevelVar)

// Debug 是否开启调试日志（通过环境变量 DEBUG 控制）
var Debug = os.Getenv("DEBUG") == "1"

// initLogger 初始化结构化日志
func initLogger() {
	opts := &slog.HandlerOptions{Level: logLevel}
	handler := slog.NewJSONHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))
}

// setLogLevel 设置日志级别
func setLogLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "info":
		logLevel.Set(slog.LevelInfo)
	case "warn", "warning":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
	}
}

// generateRequestID 生成请求 ID
func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func debugLog(msg string, args ...any) {
	if Debug {
		slog.Debug(msg, args...)
	}
}

// requestIDMiddleware 请求 ID 中间件
func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		c.Set("requestID", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// accessLogMiddleware 访问日志中间件
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
