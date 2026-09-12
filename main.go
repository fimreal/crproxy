//go:build !lite
// +build !lite

package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

var version, buildTime string

//go:embed admin/index.html
var adminHTML []byte

// DomainSuffix is the domain suffix for mirror hosts
var DomainSuffix string

// CacheDir is the local cache directory for caching responses
var CacheDir string

// StatsDir is the directory for persisting statistics
var StatsDir string

func main() {
	var help bool
	var showVersion bool
	var doUpdate bool
	var listen string
	var registryMapSource string
	var defaultRegistry string
	var logLevelStr string
	var configFile string

	flag.StringVar(&listen, "listen", ":5000", "backend listen address")
	flag.StringVar(&DomainSuffix, "domain-suffix", "", "domain suffix for mirror hosts, e.g. mydomain.com; if empty use default registry as upstream")
	flag.StringVar(&registryMapSource, "registry-map", "", "registry map file path or URL (default: embed registrymap.json)")
	flag.StringVar(&CacheDir, "cache-dir", "", "local cache directory for caching responses (optional, disabled if empty)")
	flag.StringVar(&StatsDir, "stats-dir", "", "directory for persisting statistics to JSON file (optional, disabled if empty)")
	flag.BoolVar(&help, "help", false, "show help")
	flag.StringVar(&defaultRegistry, "default-registry", "", "default registry URL, e.g. https://registry-1.docker.io")
	flag.BoolVar(&showVersion, "version", false, "show version")
	flag.StringVar(&logLevelStr, "log-level", "info", "log level: debug, info, warn, error")
	flag.StringVar(&configFile, "config-file", "", "configuration file path (default: ./crproxy-config.json)")
	flag.DurationVar(&idleTimeout, "idle-timeout", 5*time.Minute, "close connections carrying no bytes for this long, e.g. 5m, 30s; 0 disables")
	flag.BoolVar(&doUpdate, "update", false, "update to latest version from GitHub releases")
	flag.Parse()

	// 初始化日志
	initLogger()
	setLogLevel(logLevelStr)

	// 记录启动时的二进制文件信息（用于检测更新）
	if err := recordStartupBinaryInfo(); err != nil {
		slog.Warn("failed to record startup binary info", "error", err)
	}

	if showVersion {
		fmt.Printf("version: %s, build time: %s\n", version, buildTime)
		return
	}

	if help {
		flag.Usage()
		return
	}

	// 自升级
	if doUpdate {
		if err := updateSelf(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Update failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 初始化配置管理器
	if configFile == "" {
		configFile = "crproxy-config.json"
	}
	configManager := NewConfigManager(configFile)

	// 尝试加载配置文件
	if err := configManager.LoadFromFile(); err != nil {
		slog.Error("failed to load config file", "error", err)
		os.Exit(1)
	}

	// 使用命令行参数创建初始配置
	initialConfig := Config{
		RegistryMap:  make(map[string]string),
		DomainSuffix: DomainSuffix,
		LogLevel:     logLevelStr,
		CacheDir:     CacheDir,
		StatsDir:     StatsDir,
		Listen:       listen,
	}

	// 如果配置文件为空，使用命令行参数初始化
	loadedConfig := configManager.GetConfig()
	if len(loadedConfig.RegistryMap) == 0 {
		// 加载RegistryMap
		var err error
		registryMap, err := loadRegistryMap(registryMapSource)
		if err != nil {
			slog.Error("Failed to load registry map", "error", err)
			os.Exit(1)
		}
		// 命令行指定的 defaultRegistry 优先
		initialConfig.RegistryMap = effectiveRegistryMap(registryMap, defaultRegistry)
		configManager.UpdateConfig(initialConfig)
	} else {
		// 配置文件存在，使用配置文件的值，但命令行参数优先
		loadedConfig.RegistryMap = effectiveRegistryMap(loadedConfig.RegistryMap, defaultRegistry)
		if DomainSuffix != "" {
			loadedConfig.DomainSuffix = DomainSuffix
		}
		if logLevelStr != "info" {
			loadedConfig.LogLevel = logLevelStr
		}
		if CacheDir != "" {
			loadedConfig.CacheDir = CacheDir
		}
		if StatsDir != "" {
			loadedConfig.StatsDir = StatsDir
		}
		if listen != ":5000" {
			loadedConfig.Listen = listen
		}
		configManager.UpdateConfig(loadedConfig)
	}

	// 应用配置
	config := configManager.GetConfig()
	SetRegistryMap(config.RegistryMap)
	DomainSuffix = config.DomainSuffix
	CacheDir = config.CacheDir
	StatsDir = config.StatsDir
	setLogLevel(config.LogLevel)

	debugLog("registry-map available registries", "registries", GetRegistryMap())

	// 初始化缓存目录
	if CacheDir != "" {
		if err := os.MkdirAll(CacheDir, 0755); err != nil {
			slog.Error("failed to create cache directory", "cache_dir", CacheDir, "error", err)
			os.Exit(1)
		}

		slog.Info("cache enabled", "cache_dir", CacheDir)
		// 启动缓存清理器（清理崩溃遗留的临时文件）
		startCacheCleaner()
	} else {
		slog.Info("cache disabled")
	}

	// 初始化认证管理器（优先使用配置文件中的密码，环境变量作为备选）
	adminPassword := configManager.GetConfig().AdminPassword
	if adminPassword == "" {
		adminPassword = os.Getenv("ADMIN_PASSWORD")
	}
	authManager := NewAuthManager(adminPassword)
	if adminPassword == "" {
		slog.Warn("adminPassword not set in config or ADMIN_PASSWORD env, admin interface will be disabled")
	} else {
		slog.Info("admin interface enabled")
	}

	// 初始化统计收集器
	statsCollector := NewStatsCollector()

	// 加载持久化的统计数据
	if StatsDir != "" {
		statsCollector.SetStatsDir(StatsDir)
		if err := statsCollector.LoadFromFile(); err != nil {
			slog.Warn("failed to load stats from file", "error", err)
		} else {
			slog.Info("stats persistence enabled", "stats_dir", StatsDir)
		}
	}

	if !Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestIDMiddleware())
	r.Use(accessLogMiddleware(statsCollector))

	// 原有的 API 路由
	r.Any("/v2/*path", forward)
	r.Any("/token/*path", forward)

	r.GET("/help", func(c *gin.Context) {
		c.JSON(http.StatusOK, GetRegistryMap())
	})
	r.GET("/containerd", func(c *gin.Context) {
		generateContainerdHelp(c, DomainSuffix)
	})
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	// 设置管理界面路由
	setupAdminRoutes(r, authManager, configManager, statsCollector)

	// 管理界面前端页面
	r.GET("/admin", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", adminHTML)
	})
	r.GET("/admin/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", adminHTML)
	})

	// 显式持有 http.Server：在线重启与 SIGTERM 都需要先优雅关闭再退出/替换进程
	srv := &http.Server{Addr: listen, Handler: r}

	saveStats := func(reason string) {
		if StatsDir == "" {
			return
		}
		slog.Info("saving stats before "+reason+"...", "stats_dir", StatsDir)
		if err := statsCollector.SaveToFile(); err != nil {
			slog.Error("failed to save stats", "error", err)
		}
	}

	// 供「在线重启」复用：保存统计 → 停止接收新请求 → 等待在途请求结束
	restartShutdownFn = func(ctx context.Context) error {
		saveStats("restart")
		return srv.Shutdown(ctx)
	}

	// 优雅关闭：保存统计数据
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		saveStats("shutdown")
		ctx, cancel := context.WithTimeout(context.Background(), restartDrainTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Warn("graceful shutdown timed out", "error", err)
		}
		os.Exit(0)
	}()

	// 定时保存统计数据（每 5 分钟）
	if StatsDir != "" {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			for range ticker.C {
				if err := statsCollector.SaveToFile(); err != nil {
					slog.Warn("failed to save stats periodically", "error", err)
				}
			}
		}()
	}

	slog.Info("crproxy listening", "address", listen)
	if idleTimeout > 0 {
		slog.Info("idle connection timeout enabled", "timeout", idleTimeout)
	}
	if DomainSuffix != "" {
		slog.Info("domain-suffix configured", "suffix", DomainSuffix)
	} else {
		slog.Warn("domain-suffix is not set, using default registry as the solo upstream")
	}
	// 不用 srv.ListenAndServe()：套一层空闲超时，免得假死的下载连接永远占着在途任务
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		slog.Error("failed to listen", "address", listen, "error", err)
		os.Exit(1)
	}
	if err := srv.Serve(newIdleTimeoutListener(ln, idleTimeout)); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}

	// 走到这里说明 HTTP 服务已被关闭。如果是「在线重启」关的，
	// 那么新映像即将（或已经）通过 exec 接管同一个 PID，本进程绝不能退出——
	// 退出会让 systemd 拆掉 cgroup、或让容器认为主进程结束。
	if requested, errMsg := restartState.snapshot(); requested {
		slog.Info("listener closed for in-place restart, waiting for exec to take over", "last_error", errMsg)
		select {}
	}
}
