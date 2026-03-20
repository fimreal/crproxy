//go:build lite
// +build lite

package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

var version, buildTime string

//go:embed registrymap.json
var embedRegistryMap []byte

// DomainSuffix is the domain suffix for mirror hosts
var DomainSuffix string

// CacheDir is the local cache directory for caching responses
var CacheDir string

// registryMap 轻量版使用简单的 map，无需线程安全
var registryMap map[string]string

func main() {
	var help bool
	var showVersion bool
	var listen string
	var defaultRegistry string
	var logLevelStr string
	var registryMapPath string

	flag.StringVar(&listen, "listen", ":5000", "backend listen address")
	flag.StringVar(&DomainSuffix, "domain-suffix", "", "domain suffix for mirror hosts, e.g. mydomain.com; if empty use default registry as upstream")
	flag.StringVar(&CacheDir, "cache-dir", "", "local cache directory for caching responses (optional, disabled if empty)")
	flag.StringVar(&defaultRegistry, "default-registry", "", "default registry URL, e.g. https://registry-1.docker.io")
	flag.StringVar(&logLevelStr, "log-level", "info", "log level: debug, info, warn, error")
	flag.StringVar(&registryMapPath, "registry-map", "", "registry map file path (default: use built-in)")
	flag.BoolVar(&help, "help", false, "show help")
	flag.BoolVar(&showVersion, "version", false, "show version")
	flag.Parse()

	// 初始化日志
	initLogger()
	setLogLevel(logLevelStr)

	if showVersion {
		fmt.Printf("version: %s, build time: %s\n", version, buildTime)
		return
	}

	if help {
		flag.Usage()
		return
	}

	// 加载 registry map
	if registryMapPath != "" {
		data, err := os.ReadFile(registryMapPath)
		if err != nil {
			slog.Error("failed to read registry map file", "error", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &registryMap); err != nil {
			slog.Error("failed to parse registry map", "error", err)
			os.Exit(1)
		}
	} else {
		if err := json.Unmarshal(embedRegistryMap, &registryMap); err != nil {
			slog.Error("failed to parse built-in registry map", "error", err)
			os.Exit(1)
		}
	}

	// 设置默认 registry
	if defaultRegistry != "" {
		registryMap["default"] = defaultRegistry
	} else if registryMap["default"] == "" {
		// 如果没有指定默认 registry，使用第一个非 default 的
		for k, v := range registryMap {
			if k != "default" && v != "" {
				registryMap["default"] = v
				break
			}
		}
	}

	// 初始化缓存目录
	if CacheDir != "" {
		if err := os.MkdirAll(CacheDir, 0755); err != nil {
			slog.Error("failed to create cache directory", "cache_dir", CacheDir, "error", err)
			os.Exit(1)
		}
		slog.Info("cache enabled", "cache_dir", CacheDir)
		startCacheCleaner()
	} else {
		slog.Info("cache disabled")
	}

	if !Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestIDMiddleware())
	r.Use(accessLogMiddleware())

	// 核心代理路由
	r.Any("/v2/*path", forward)
	r.Any("/token/*path", forward)

	// 健康检查
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	slog.Info("crproxy-lite listening", "address", listen)
	if DomainSuffix != "" {
		slog.Info("domain-suffix configured", "suffix", DomainSuffix)
	} else {
		slog.Info("running in single-upstream mode")
	}
	if err := r.Run(listen); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// GetRegistryMap 获取 registry map（轻量版）
func GetRegistryMap() map[string]string {
	return registryMap
}
