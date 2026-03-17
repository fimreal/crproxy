package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed registrymap.json
var embedRegistryMap []byte

// RegistryMap 镜像仓库地址（使用 atomic.Value 实现线程安全的原子替换）
var registryMap atomic.Value

// GetRegistryMap 获取当前的 RegistryMap
func GetRegistryMap() map[string]string {
	if m, ok := registryMap.Load().(map[string]string); ok {
		return m
	}
	return make(map[string]string)
}

// SetRegistryMap 原子替换 RegistryMap
func SetRegistryMap(m map[string]string) {
	registryMap.Store(m)
}

// Config 动态配置结构
type Config struct {
	RegistryMap     map[string]string `json:"registryMap"`
	DefaultRegistry string            `json:"defaultRegistry"`
	DomainSuffix    string            `json:"domainSuffix"`
	LogLevel        string            `json:"logLevel"`
	CacheDir        string            `json:"cacheDir"`
	Listen          string            `json:"listen"`
	AdminPassword   string            `json:"adminPassword"`
}

// ConfigManager 配置管理器（线程安全）
type ConfigManager struct {
	mu       sync.RWMutex
	config   Config
	filePath string
}

// NewConfigManager 创建配置管理器
func NewConfigManager(filePath string) *ConfigManager {
	return &ConfigManager{
		filePath: filePath,
		config:   Config{RegistryMap: make(map[string]string)},
	}
}

// GetConfig 获取当前配置（返回副本）
func (cm *ConfigManager) GetConfig() Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// 返回副本，避免外部修改
	config := cm.config
	config.RegistryMap = make(map[string]string)
	for k, v := range cm.config.RegistryMap {
		config.RegistryMap[k] = v
	}
	return config
}

// UpdateConfig 更新配置
func (cm *ConfigManager) UpdateConfig(newConfig Config) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 验证配置
	if newConfig.DefaultRegistry != "" {
		if _, err := url.Parse(newConfig.DefaultRegistry); err != nil {
			return fmt.Errorf("invalid default-registry URL: %w", err)
		}
	}

	// 验证 RegistryMap 中的 URL
	for name, registryURL := range newConfig.RegistryMap {
		if _, err := url.Parse(registryURL); err != nil {
			return fmt.Errorf("invalid registry URL for %s: %w", name, err)
		}
	}

	// 更新内存配置
	cm.config = newConfig
	if cm.config.RegistryMap == nil {
		cm.config.RegistryMap = make(map[string]string)
	}

	// 持久化到文件
	if err := cm.saveToFile(); err != nil {
		slog.Error("failed to save config file", "error", err)
		return err
	}

	return nil
}

// LoadFromFile 从文件加载配置
func (cm *ConfigManager) LoadFromFile() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	data, err := os.ReadFile(cm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在不是错误
		}
		return err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	if config.RegistryMap == nil {
		config.RegistryMap = make(map[string]string)
	}

	cm.config = config
	return nil
}

// saveToFile 保存配置到文件（原子写入）
func (cm *ConfigManager) saveToFile() error {
	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return err
	}

	// 原子写入：先写临时文件，再 rename
	// 配置文件可能包含敏感信息，设置权限为 0600（仅所有者可读写）
	tmpFile := cm.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpFile, cm.filePath)
}

// loadRegistryMap 从文件或URL加载 RegistryMap
func loadRegistryMap(source string) (map[string]string, error) {
	var data []byte
	var err error

	// 如果没有指定源，则使用内置的 RegistryMap
	if source == "" {
		data = embedRegistryMap
		slog.Info("using built-in registry map")
	} else {
		// 从外部源加载 RegistryMap
		client := &http.Client{Timeout: 30 * time.Second}
		var resp *http.Response

		if strings.HasPrefix(source, "http") {
			resp, err = client.Get(source)
			if err != nil {
				return nil, fmt.Errorf("failed to load registry map from URL %s: %v", source, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("ERROR HTTP %d: %s", resp.StatusCode, resp.Status)
			}
			slog.Info("loaded registry map from URL", "source", source)
			data, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("ERROR failed to read response body: %v", err)
			}
		} else {
			// 从本地文件加载
			data, err = os.ReadFile(source)
			if err != nil {
				return nil, fmt.Errorf("ERROR failed to read registry map file %s: %v", source, err)
			}
			slog.Info("registry-map: loaded registry map from file", "source", source)
		}
	}

	// 解析JSON
	var registryMap map[string]string
	err = json.Unmarshal(data, &registryMap)
	if err != nil {
		return nil, fmt.Errorf("ERROR failed to parse registry map JSON: %v", err)
	}

	// 如果没有指定默认 registry，则任意选取其一
	if registryMap["default"] == "" && len(registryMap) > 0 {
		for k, v := range registryMap {
			if k != "default" && v != "" {
				// 验证 URL 格式
				if _, err := url.Parse(v); err == nil {
					registryMap["default"] = v
					break
				}
			}
		}
	}

	return registryMap, nil
}
