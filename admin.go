//go:build !lite
// +build !lite

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// setupAdminRoutes 设置管理界面路由
func setupAdminRoutes(r *gin.Engine, authManager *AuthManager, configManager *ConfigManager, statsCollector *StatsCollector) {
	// 登录速率限制器：每秒最多 5 次登录尝试
	loginLimiter := rate.NewLimiter(rate.Every(time.Second/5), 5)

	// 登录接口（无需认证）
	r.POST("/admin/api/login", func(c *gin.Context) {
		// 检查速率限制
		if !loginLimiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many login attempts. Please wait."})
			return
		}

		if authManager.GetPassword() == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin interface is disabled. Set ADMIN_PASSWORD environment variable to enable."})
			return
		}

		var req struct {
			Password string `json:"password"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		token, err := authManager.Login(req.Password)
		if err != nil {
			slog.Warn("login failed", "client_ip", c.ClientIP(), "error", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			return
		}

		slog.Info("login successful", "client_ip", c.ClientIP())
		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	// 认证中间件
	authMiddlewareFunc := func(c *gin.Context) {
		if authManager.GetPassword() == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin interface is disabled"})
			c.Abort()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if !authManager.ValidateToken(authHeader) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}

	// 管理 API 路由组（需要认证）
	adminAPI := r.Group("/admin/api")
	adminAPI.Use(authMiddlewareFunc)
	{
		// 获取配置
		adminAPI.GET("/config", func(c *gin.Context) {
			config := configManager.GetConfig()
			c.JSON(http.StatusOK, config)
		})

		// 更新配置
		adminAPI.PUT("/config", func(c *gin.Context) {
			var newConfig Config
			if err := c.BindJSON(&newConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
				return
			}

			if err := configManager.UpdateConfig(newConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			// 应用配置（实时生效）
			applyRuntimeConfig(newConfig)

			slog.Info("config updated", "client_ip", c.ClientIP())
			c.JSON(http.StatusOK, gin.H{"message": "Configuration updated successfully"})
		})

		// 添加 registry 映射
		adminAPI.POST("/registry", func(c *gin.Context) {
			var req struct {
				Name string `json:"name"`
				URL  string `json:"url"`
			}
			if err := c.BindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
				return
			}

			if req.Name == "" || req.URL == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Name and URL are required"})
				return
			}

			// 验证 URL
			if _, err := url.Parse(req.URL); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid URL"})
				return
			}

			// 更新配置
			config := configManager.GetConfig()
			if config.RegistryMap == nil {
				config.RegistryMap = make(map[string]string)
			}
			config.RegistryMap[req.Name] = req.URL

			if err := configManager.UpdateConfig(config); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			// 应用配置
			SetRegistryMap(config.RegistryMap)

			slog.Info("registry added", "name", req.Name, "url", req.URL)
			c.JSON(http.StatusOK, gin.H{"message": "Registry added successfully"})
		})

		// 删除 registry 映射
		adminAPI.DELETE("/registry/:name", func(c *gin.Context) {
			name := c.Param("name")

			if name == "default" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete default registry"})
				return
			}

			config := configManager.GetConfig()
			if _, exists := config.RegistryMap[name]; !exists {
				c.JSON(http.StatusNotFound, gin.H{"error": "Registry not found"})
				return
			}

			delete(config.RegistryMap, name)
			if err := configManager.UpdateConfig(config); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			// 应用配置
			SetRegistryMap(config.RegistryMap)

			slog.Info("registry deleted", "name", name)
			c.JSON(http.StatusOK, gin.H{"message": "Registry deleted successfully"})
		})

		// 获取统计
		adminAPI.GET("/stats", func(c *gin.Context) {
			stats := statsCollector.GetStats()
			c.JSON(http.StatusOK, stats)
		})

		// 实时状态快照（实时监控 tab 使用）
		adminAPI.GET("/live", func(c *gin.Context) {
			c.JSON(http.StatusOK, live.Snapshot())
		})

		// 获取缓存统计
		adminAPI.GET("/cache/stats", func(c *gin.Context) {
			if CacheDir == "" {
				c.JSON(http.StatusOK, gin.H{
					"enabled": false,
				})
				return
			}

			var totalSize int64
			var blobCount int
			var metaCount int
			err := filepath.Walk(CacheDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					// 分别统计 blob 和 meta 文件
					if strings.HasSuffix(path, blobSuffix) {
						totalSize += info.Size()
						blobCount++
					} else if strings.HasSuffix(path, metaSuffix) {
						metaCount++
					}
				}
				return nil
			})

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"enabled":    true,
				"dir":        CacheDir,
				"totalSize":  totalSize,
				"blobCount":  blobCount, // 实际缓存的镜像层数量
				"metaCount":  metaCount, // 元数据文件数量
				"fileCount":  blobCount, // 保持兼容性，实际是 blob 数量
				"totalFiles": blobCount + metaCount,
			})
		})

		// 清空缓存
		adminAPI.POST("/cache/clear", func(c *gin.Context) {
			if CacheDir == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cache not enabled"})
				return
			}

			// 加锁保护缓存清理操作
			cacheMutex.Lock()
			defer cacheMutex.Unlock()

			files, err := os.ReadDir(CacheDir)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			var deleted int
			var errors []string
			for _, file := range files {
				if err := os.RemoveAll(filepath.Join(CacheDir, file.Name())); err != nil {
					errors = append(errors, err.Error())
				} else {
					deleted++
				}
			}

			slog.Info("cache cleared", "deleted_files", deleted, "errors", len(errors))
			c.JSON(http.StatusOK, gin.H{
				"deleted": deleted,
				"errors":  errors,
			})
		})

		// 检查更新
		adminAPI.GET("/update/check", func(c *gin.Context) {
			// 先检查是否需要重启
			pending, err := isRestartPending()
			if err != nil {
				slog.Warn("failed to check restart status", "error", err)
			}

			info, err := checkForUpdate()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			// 如果需要重启，在返回信息中标注
			response := gin.H{
				"currentVersion": info.CurrentVersion,
				"latestVersion":  info.LatestVersion,
				"hasUpdate":      info.HasUpdate,
				"restartPending": pending,
			}

			c.JSON(http.StatusOK, response)
		})

		// 执行更新
		adminAPI.POST("/update", func(c *gin.Context) {
			latestVersion, err := performUpdate()
			if err != nil {
				if errors.Is(err, ErrUpdateInProgress) {
					c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			if latestVersion == "" {
				c.JSON(http.StatusOK, gin.H{
					"message":        "Already at the latest version",
					"currentVersion": version,
				})
				return
			}
			slog.Info("binary updated", "new_version", latestVersion, "client_ip", c.ClientIP())
			c.JSON(http.StatusOK, gin.H{
				"message":        "Update successful. Please restart the service.",
				"currentVersion": version,
				"newVersion":     latestVersion,
			})
		})

		// 更新进度（更新过程中前端轮询这里显示进度条）
		adminAPI.GET("/update/progress", func(c *gin.Context) {
			c.JSON(http.StatusOK, updateProgress.snapshot())
		})

		// 运行环境与重启能力（重启 tab 使用）
		adminAPI.GET("/restart/info", func(c *gin.Context) {
			c.JSON(http.StatusOK, restartInfo())
		})

		// 重启服务：先回包，再优雅关闭并原地 exec（保持 PID 不变）
		adminAPI.POST("/restart", func(c *gin.Context) {
			if !restartSupported {
				c.JSON(http.StatusConflict, gin.H{"error": "in-place restart is not supported on this platform"})
				return
			}
			if progress := updateProgress.snapshot(); progress.Running {
				c.JSON(http.StatusConflict, gin.H{"error": ErrUpdateInProgress.Error()})
				return
			}
			if !requestRestart() {
				c.JSON(http.StatusConflict, gin.H{"error": "a restart is already in progress"})
				return
			}

			slog.Info("restart requested via admin api", "client_ip", c.ClientIP(), "pid", os.Getpid())
			// 先把响应发出去，重启在后台延迟执行（见 performRestart）
			c.JSON(http.StatusOK, gin.H{
				"restarting": true,
				"method":     restartMethodName,
				"pid":        os.Getpid(),
			})
			go performRestart()
		})

		// 取消重启：仅在「等待在途下载结束」阶段有效。
		// 一旦进入优雅关闭/exec，等待已结束，取消请求会被拒绝（409）。
		adminAPI.POST("/restart/cancel", func(c *gin.Context) {
			if !restartState.requestCancel() {
				c.JSON(http.StatusConflict, gin.H{"error": "no cancellable restart in progress"})
				return
			}
			slog.Info("restart canceled via admin api", "client_ip", c.ClientIP())
			c.JSON(http.StatusOK, gin.H{"canceled": true})
		})

		// 重载配置
		adminAPI.POST("/config/reload", func(c *gin.Context) {
			// 从文件重新加载配置
			if err := configManager.LoadFromFile(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to load config file: %v", err)})
				return
			}

			// 应用配置
			config := configManager.GetConfig()
			applyRuntimeConfig(config)

			slog.Info("config reloaded", "client_ip", c.ClientIP())
			c.JSON(http.StatusOK, gin.H{
				"message": "Configuration reloaded successfully",
				"config":  config,
			})
		})
	}
}
