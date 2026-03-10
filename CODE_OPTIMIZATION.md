# 代码优化建议

## 🔴 高优先级问题

### 1. 并发安全问题：全局变量 RegistryMap

**位置**: `main.go:1319`

**问题**:
```go
RegistryMap = config.RegistryMap  // 直接赋值，可能有并发访问问题
```

RegistryMap 是全局变量，在多个 goroutine 中被读取（通过 `findRegistryURL`），当通过 API 更新时直接替换整个 map，可能导致并发读写问题。

**解决方案**:
使用 `sync.Map` 或者在更新时使用原子替换：

```go
// 方案1: 使用 sync.Map（推荐）
var RegistryMap sync.Map

// 读取时
func findRegistryURL(host string) (*url.URL, error) {
    if v, ok := RegistryMap.Load(name); ok {
        return v.(string), true
    }
    // ...
}

// 更新时
func updateRegistryMap(newMap map[string]string) {
    RegistryMap.Clear()
    for k, v := range newMap {
        RegistryMap.Store(k, v)
    }
}

// 方案2: 使用原子替换
var registryMap atomic.Value

func getRegistryMap() map[string]string {
    if m, ok := registryMap.Load().(map[string]string); ok {
        return m
    }
    return nil
}

func setRegistryMap(m map[string]string) {
    registryMap.Store(m)
}
```

### 2. 缓存清理时的并发安全问题

**位置**: `main.go:1569-1599`

**问题**:
清空缓存时没有锁定缓存目录，可能导致：
- 正在写入缓存的请求失败
- 删除过程中有新文件写入
- 与 `startCacheCleaner()` 冲突

**解决方案**:
```go
// 添加缓存互斥锁
var cacheMutex sync.RWMutex

// 在清空缓存时加锁
adminAPI.POST("/cache/clear", func(c *gin.Context) {
    if CacheDir == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Cache not enabled"})
        return
    }

    cacheMutex.Lock()
    defer cacheMutex.Unlock()

    // 清理逻辑...
})

// 在写入缓存时加读锁
func writeToCache(resp *http.Response) {
    cacheMutex.RLock()
    defer cacheMutex.RUnlock()
    // 写入逻辑...
}
```

### 3. Token 过期清理时机问题

**位置**: `main.go:316, 350`

**问题**:
- `cleanExpiredTokens()` 只在登录时调用，长时间运行的服务会积累大量过期 token
- `ValidateToken()` 中检测到过期 token 但不删除，可能导致内存泄漏

**解决方案**:
```go
// 方案1: 定期清理（推荐）
func (am *AuthManager) startCleanupTask() {
    go func() {
        ticker := time.NewTicker(1 * time.Hour)
        defer ticker.Stop()

        for range ticker.C {
            am.mu.Lock()
            am.cleanExpiredTokens()
            am.mu.Unlock()
        }
    }()
}

// 在创建 AuthManager 时启动
func NewAuthManager(password string) *AuthManager {
    am := &AuthManager{
        password: password,
        tokens:   make(map[string]time.Time),
    }
    am.startCleanupTask()
    return am
}

// 方案2: 在验证时删除过期 token
func (am *AuthManager) ValidateToken(authHeader string) bool {
    // ...
    am.mu.Lock()
    defer am.mu.Unlock()

    if expiry, exists := am.tokens[token]; exists {
        if time.Now().After(expiry) {
            delete(am.tokens, token) // 删除过期 token
            return false
        }
        return true
    }
    return false
}
```

## 🟡 中优先级问题

### 4. 配置文件权限问题

**位置**: `main.go:271`

**问题**:
配置文件可能包含敏感信息，但权限设置为 `0644`（所有人可读）。

**解决方案**:
```go
// 保存配置文件时设置更严格的权限
if err := os.WriteFile(tmpFile, data, 0600); err != nil {
    return err
}
```

### 5. 错误处理不充分

**位置**: `main.go:1296, 1314`

**问题**:
`configManager.UpdateConfig()` 失败时没有返回错误，继续执行。

**解决方案**:
```go
if len(loadedConfig.RegistryMap) == 0 {
    // ...
    initialConfig.RegistryMap = registryMap
    if err := configManager.UpdateConfig(initialConfig); err != nil {
        slog.Error("failed to initialize config", "error", err)
        os.Exit(1)
    }
} else {
    // ...
    if err := configManager.UpdateConfig(loadedConfig); err != nil {
        slog.Error("failed to update config", "error", err)
        os.Exit(1)
    }
}
```

### 6. 缺少速率限制

**位置**: `main.go:1397-1420` (登录接口)

**问题**:
登录接口没有速率限制，可能被暴力破解。

**解决方案**:
```go
import "golang.org/x/time/rate"

var loginLimiter = rate.NewLimiter(rate.Every(time.Second), 5) // 每秒最多5次

r.POST("/admin/api/login", func(c *gin.Context) {
    if !loginLimiter.Allow() {
        c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many login attempts"})
        return
    }
    // 登录逻辑...
})
```

### 7. URL 验证不够严格

**位置**: `main.go:209, 216`

**问题**:
只验证 URL 格式，不验证协议和可达性。

**解决方案**:
```go
func validateRegistryURL(urlStr string) error {
    u, err := url.Parse(urlStr)
    if err != nil {
        return err
    }

    // 验证协议
    if u.Scheme != "https" && u.Scheme != "http" {
        return fmt.Errorf("invalid scheme: %s (must be http or https)", u.Scheme)
    }

    // 验证主机名
    if u.Host == "" {
        return fmt.Errorf("missing host in URL")
    }

    return nil
}
```

## 🟢 低优先级优化

### 8. 配置结构体优化

**建议**:
添加字段标签和文档注释：

```go
type Config struct {
    RegistryMap     map[string]string `json:"registryMap" yaml:"registryMap"`
    DefaultRegistry string            `json:"defaultRegistry" yaml:"defaultRegistry"`
    DomainSuffix    string            `json:"domainSuffix" yaml:"domainSuffix"`
    LogLevel        string            `json:"logLevel" yaml:"logLevel"`
    CacheDir        string            `json:"cacheDir" yaml:"cacheDir"`
    Listen          string            `json:"listen" yaml:"listen"`
}

// Validate 验证配置有效性
func (c *Config) Validate() error {
    // 验证逻辑
    return nil
}
```

### 9. 统计信息持久化

**建议**:
当前统计信息在重启后丢失，可以添加持久化：

```go
func (sc *StatsCollector) SaveToFile(path string) error {
    data := sc.GetStats()
    jsonBytes, _ := json.Marshal(data)
    return os.WriteFile(path, jsonBytes, 0644)
}

func (sc *StatsCollector) LoadFromFile(path string) error {
    data, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    var stats map[string]int64
    json.Unmarshal(data, &stats)
    // 恢复统计值
    return nil
}
```

### 10. 内存优化：复制 RegistryMap

**位置**: `main.go:195-198`

**建议**:
使用 `maps.Copy` 简化代码（Go 1.21+）：

```go
import "maps"

func (cm *ConfigManager) GetConfig() Config {
    cm.mu.RLock()
    defer cm.mu.RUnlock()

    config := cm.config
    config.RegistryMap = maps.Clone(cm.config.RegistryMap)
    return config
}
```

### 11. 添加健康检查详细信息

**建议**:
扩展 `/healthz` 端点，返回更多诊断信息：

```go
r.GET("/healthz", func(c *gin.Context) {
    health := gin.H{
        "status": "ok",
        "version": version,
        "uptime": time.Since(startTime).String(),
        "cache": gin.H{
            "enabled": CacheDir != "",
            "size": getCacheSize(),
        },
        "registries": len(RegistryMap),
    }
    c.JSON(http.StatusOK, health)
})
```

### 12. 添加配置变更审计日志

**建议**:
记录谁在什么时候修改了什么配置：

```go
func (cm *ConfigManager) UpdateConfig(newConfig Config, changedBy string) error {
    oldConfig := cm.GetConfig()

    // 记录变更
    slog.Info("config updated",
        "by", changedBy,
        "changes", diffConfigs(oldConfig, newConfig),
        "client_ip", changedBy,
    )

    // 更新配置...
}
```

## 🔧 代码质量改进

### 13. 添加单元测试

建议为以下组件添加测试：
- `ConfigManager` 的并发安全性
- `AuthManager` 的 token 生成和验证
- `StatsCollector` 的统计准确性
- API 端点的正确性

### 14. 添加 API 文档

使用 Swagger/OpenAPI 文档化 API：

```go
// @Summary Login to admin interface
// @Description Authenticate with password and get access token
// @Accept json
// @Produce json
// @Param password body LoginRequest true "Login credentials"
// @Success 200 {object} TokenResponse
// @Failure 401 {object} ErrorResponse
// @Router /admin/api/login [post]
r.POST("/admin/api/login", handleLogin)
```

### 15. 优化前端资源加载

**建议**:
- 压缩 HTML/CSS/JavaScript
- 添加前端构建流程（可选）
- 考虑使用 CDN 加载 CSS 框架

## 📊 性能优化

### 16. 缓存目录遍历优化

**位置**: `main.go:1543-1559`

**问题**:
每次请求 `/admin/api/cache/stats` 都遍历整个缓存目录，可能很慢。

**解决方案**:
```go
// 缓存统计信息，定期更新
var cachedStats atomic.Value
var statsUpdateTimer *time.Timer

func startStatsCacheUpdater() {
    go func() {
        ticker := time.NewTicker(5 * time.Minute)
        defer ticker.Stop()

        for range ticker.C {
            stats := calculateCacheStats()
            cachedStats.Store(stats)
        }
    }()
}

func getCacheStats() gin.H {
    if v := cachedStats.Load(); v != nil {
        return v.(gin.H)
    }
    return calculateCacheStats() // 首次请求时计算
}
```

## 🔒 安全加固

### 17. 添加 HTTPS 支持

**建议**:
```go
// 在 main() 中添加 TLS 支持
if certFile != "" && keyFile != "" {
    slog.Info("enabling TLS", "cert", certFile, "key", keyFile)
    if err := r.RunTLS(listen, certFile, keyFile); err != nil {
        slog.Error("server failed", "error", err)
        os.Exit(1)
    }
} else {
    if err := r.Run(listen); err != nil {
        slog.Error("server failed", "error", err)
        os.Exit(1)
    }
}
```

### 18. 添加 CORS 配置

**建议**:
如果需要跨域访问：
```go
import "github.com/gin-contrib/cors"

r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"https://yourdomain.com"},
    AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
    AllowHeaders:     []string{"Authorization", "Content-Type"},
    ExposeHeaders:    []string{"Content-Length"},
    AllowCredentials: true,
}))
```

## 优先级总结

1. **立即修复**: RegistryMap 并发安全、缓存清理并发、Token 清理
2. **重要优化**: 配置文件权限、错误处理、登录速率限制
3. **长期改进**: 单元测试、API 文档、性能优化

建议按优先级逐步实施这些优化。
