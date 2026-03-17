package main

import (
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
			SetRegistryMap(newConfig.RegistryMap)
			DomainSuffix = newConfig.DomainSuffix
			setLogLevel(newConfig.LogLevel)

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

		// 重载配置
		adminAPI.POST("/config/reload", func(c *gin.Context) {
			// 从文件重新加载配置
			if err := configManager.LoadFromFile(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to load config file: %v", err)})
				return
			}

			// 应用配置
			config := configManager.GetConfig()
			SetRegistryMap(config.RegistryMap)
			DomainSuffix = config.DomainSuffix
			setLogLevel(config.LogLevel)

			slog.Info("config reloaded", "client_ip", c.ClientIP())
			c.JSON(http.StatusOK, gin.H{
				"message": "Configuration reloaded successfully",
				"config":  config,
			})
		})
	}
}
