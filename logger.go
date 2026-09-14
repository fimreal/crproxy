package main

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// 日志级别
var logLevel = new(slog.LevelVar)

// debugFromEnv 记录环境变量 DEBUG=1 的初始意图。
// 单独存一份是因为 setLogLevel 每次都会重算 Debug：日志级别调回 info 时
// 不能顺手把用户用环境变量开的调试日志关掉。
var debugFromEnv = os.Getenv("DEBUG") == "1"

// Debug 是否开启调试日志（环境变量 DEBUG=1，或日志级别为 debug）
var Debug = debugFromEnv

// initLogger 初始化结构化日志
func initLogger() {
	opts := &slog.HandlerOptions{Level: logLevel}
	handler := slog.NewJSONHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))
}

// setLogLevel 设置日志级别
func setLogLevel(level string) {
	level = strings.ToLower(level)
	// DEBUG=1 的意图就是「我要看调试日志」。只开 Debug 开关不够——
	// slog 级别还是 info，slog.Debug 照样被吃掉，环境变量等于没写。
	if debugFromEnv && (level == "" || level == "info") {
		level = "debug"
	}
	// debugLog() 走的是 Debug 开关而不是 slog 级别，只认环境变量的话，
	// 配置文件里写 logLevel=debug 就成了摆设 —— 这里统一重算，两条路都通。
	Debug = debugFromEnv || level == "debug"

	switch level {
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
