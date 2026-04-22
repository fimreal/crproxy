//go:build !lite
// +build !lite

package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ClientStats 客户端统计（请求数 + 流量）
type ClientStats struct {
	Requests int64 `json:"requests"`
	Bytes    int64 `json:"bytes"`
}

// StatsCollector 统计收集器
type StatsCollector struct {
	totalRequests   int64
	cacheHits       int64
	cacheMisses     int64
	startTime       time.Time
	clients         sync.Map // map[string]*ClientStats - client type -> stats
	upstreams       sync.Map // map[string]int64 - upstream host -> count
	images          sync.Map // map[string]int64 - image name -> count
	clientIPs       sync.Map // map[string]*ClientStats - client IP -> stats
	bytesSent       int64    // 发送给客户端的流量
	bytesReceived   int64    // 从上游仓库接收的流量
	activeConns     int64    // 当前活跃连接数
	bytesRateWindow int64    // 当前时间窗口内传输的字节数
	rateWindowStart int64    // 当前时间窗口开始时间（unix nano）
	rateMutex       sync.Mutex
	statsDir        string
}

// statsFileName 统计文件名
const statsFileName = "stats.json"

// NewStatsCollector 创建统计收集器
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		startTime: time.Now(),
	}
}

// SetStatsDir 设置统计持久化目录
func (sc *StatsCollector) SetStatsDir(dir string) {
	sc.statsDir = dir
}

// LoadFromFile 从文件加载统计数据
func (sc *StatsCollector) LoadFromFile() error {
	if sc.statsDir == "" {
		return nil
	}

	filePath := filepath.Join(sc.statsDir, statsFileName)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// 支持新旧两种格式
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// 恢复基本计数器
	if v, ok := raw["totalRequests"].(float64); ok {
		atomic.StoreInt64(&sc.totalRequests, int64(v))
	}
	if v, ok := raw["cacheHits"].(float64); ok {
		atomic.StoreInt64(&sc.cacheHits, int64(v))
	}
	if v, ok := raw["cacheMisses"].(float64); ok {
		atomic.StoreInt64(&sc.cacheMisses, int64(v))
	}
	if v, ok := raw["bytesSent"].(float64); ok {
		atomic.StoreInt64(&sc.bytesSent, int64(v))
	}
	if v, ok := raw["bytesReceived"].(float64); ok {
		atomic.StoreInt64(&sc.bytesReceived, int64(v))
	}

	// 恢复 clients（支持新旧格式）
	if clients, ok := raw["clients"].(map[string]any); ok {
		for k, v := range clients {
			s := new(ClientStats)
			switch val := v.(type) {
			case float64: // 旧格式：只有计数
				s.Requests = int64(val)
			case map[string]any: // 新格式：{requests, bytes}
				if r, ok := val["requests"].(float64); ok {
					s.Requests = int64(r)
				}
				if b, ok := val["bytes"].(float64); ok {
					s.Bytes = int64(b)
				}
			}
			sc.clients.Store(k, s)
		}
	}

	// 恢复 upstreams
	if upstreams, ok := raw["upstreams"].(map[string]any); ok {
		for k, v := range upstreams {
			if val, ok := v.(float64); ok {
				ptr := new(int64)
				*ptr = int64(val)
				sc.upstreams.Store(k, ptr)
			}
		}
	}

	// 恢复 images
	if images, ok := raw["images"].(map[string]any); ok {
		for k, v := range images {
			if val, ok := v.(float64); ok {
				ptr := new(int64)
				*ptr = int64(val)
				sc.images.Store(k, ptr)
			}
		}
	}

	// 恢复 clientIPs（支持新旧格式）
	if clientIPs, ok := raw["clientIPs"].(map[string]any); ok {
		for k, v := range clientIPs {
			s := new(ClientStats)
			switch val := v.(type) {
			case float64:
				s.Requests = int64(val)
			case map[string]any:
				if r, ok := val["requests"].(float64); ok {
					s.Requests = int64(r)
				}
				if b, ok := val["bytes"].(float64); ok {
					s.Bytes = int64(b)
				}
			}
			sc.clientIPs.Store(k, s)
		}
	}

	slog.Info("loaded stats from file", "path", filePath)
	return nil
}

// SaveToFile 保存统计数据到文件
func (sc *StatsCollector) SaveToFile() error {
	if sc.statsDir == "" {
		return nil
	}

	if err := os.MkdirAll(sc.statsDir, 0755); err != nil {
		return err
	}

	// 收集 clients
	clients := make(map[string]ClientStats)
	sc.clients.Range(func(key, value any) bool {
		s := value.(*ClientStats)
		clients[key.(string)] = ClientStats{
			Requests: atomic.LoadInt64(&s.Requests),
			Bytes:    atomic.LoadInt64(&s.Bytes),
		}
		return true
	})

	// 收集 upstreams
	upstreams := make(map[string]int64)
	sc.upstreams.Range(func(key, value any) bool {
		upstreams[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})

	// 收集 images
	images := make(map[string]int64)
	sc.images.Range(func(key, value any) bool {
		images[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})

	// 收集 clientIPs
	clientIPs := make(map[string]ClientStats)
	sc.clientIPs.Range(func(key, value any) bool {
		s := value.(*ClientStats)
		clientIPs[key.(string)] = ClientStats{
			Requests: atomic.LoadInt64(&s.Requests),
			Bytes:    atomic.LoadInt64(&s.Bytes),
		}
		return true
	})

	saved := struct {
		TotalRequests int64                `json:"totalRequests"`
		CacheHits     int64                `json:"cacheHits"`
		CacheMisses   int64                `json:"cacheMisses"`
		Clients       map[string]ClientStats `json:"clients"`
		Upstreams     map[string]int64     `json:"upstreams"`
		Images        map[string]int64     `json:"images"`
		ClientIPs     map[string]ClientStats `json:"clientIPs"`
		BytesSent     int64                `json:"bytesSent"`
		BytesReceived int64                `json:"bytesReceived"`
		SavedAt       string               `json:"savedAt"`
	}{
		TotalRequests: atomic.LoadInt64(&sc.totalRequests),
		CacheHits:     atomic.LoadInt64(&sc.cacheHits),
		CacheMisses:   atomic.LoadInt64(&sc.cacheMisses),
		Clients:       clients,
		Upstreams:     upstreams,
		Images:        images,
		ClientIPs:     clientIPs,
		BytesSent:     atomic.LoadInt64(&sc.bytesSent),
		BytesReceived: atomic.LoadInt64(&sc.bytesReceived),
		SavedAt:       time.Now().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join(sc.statsDir, statsFileName)
	tmpFile := filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}

	return os.Rename(tmpFile, filePath)
}

// parseClientType 从 User-Agent 解析客户端类型
func parseClientType(userAgent string) string {
	if userAgent == "" {
		return "unknown"
	}
	ua := strings.ToLower(userAgent)

	if strings.Contains(ua, "docker") {
		return "docker"
	}
	if strings.Contains(ua, "podman") || strings.Contains(ua, "libpod") {
		return "podman"
	}
	if strings.Contains(ua, "containerd") {
		return "containerd"
	}
	if strings.Contains(ua, "crane") {
		return "crane"
	}
	if strings.Contains(ua, "skopeo") {
		return "skopeo"
	}
	if strings.Contains(ua, "buildah") {
		return "buildah"
	}
	if strings.Contains(ua, "nerdctl") {
		return "nerdctl"
	}
	if strings.Contains(ua, "go-http-client") {
		return "go-http-client"
	}
	if strings.Contains(ua, "python-requests") {
		return "python-requests"
	}
	if strings.Contains(ua, "curl") {
		return "curl"
	}
	if strings.Contains(ua, "wget") {
		return "wget"
	}
	if strings.Contains(ua, "harbor") {
		return "harbor"
	}
	if strings.Contains(ua, "aws-sdk") {
		return "aws-sdk"
	}

	return "other"
}

// parseImageName 从请求路径解析镜像名称
func parseImageName(path string) string {
	if !strings.HasPrefix(path, "/v2/") {
		return ""
	}

	path = strings.TrimPrefix(path, "/v2/")

	delimiters := []string{"/manifests/", "/blobs/", "/tags/", "/blobs/uploads/"}
	for _, delim := range delimiters {
		if idx := strings.Index(path, delim); idx > 0 {
			imageName := path[:idx]
			if len(imageName) > 100 {
				imageName = imageName[:100]
			}
			return imageName
		}
	}

	return ""
}

// IncrementRequests 增加请求计数
func (sc *StatsCollector) IncrementRequests() {
	atomic.AddInt64(&sc.totalRequests, 1)
}

// IncrementCacheHits 增加缓存命中计数
func (sc *StatsCollector) IncrementCacheHits() {
	atomic.AddInt64(&sc.cacheHits, 1)
}

// IncrementCacheMisses 增加缓存未命中计数
func (sc *StatsCollector) IncrementCacheMisses() {
	atomic.AddInt64(&sc.cacheMisses, 1)
}

// incrementMapCounter 通用的 map 计数器（用于 upstreams 和 images）
func (sc *StatsCollector) incrementMapCounter(m *sync.Map, key string) {
	for {
		val, loaded := m.LoadOrStore(key, new(int64))
		counter := val.(*int64)
		if loaded {
			old := atomic.LoadInt64(counter)
			if atomic.CompareAndSwapInt64(counter, old, old+1) {
				return
			}
		} else {
			atomic.AddInt64(counter, 1)
			return
		}
	}
}

// IncrementClient 增加客户端类型统计（请求+流量）
func (sc *StatsCollector) IncrementClient(clientType string) {
	for {
		val, loaded := sc.clients.LoadOrStore(clientType, &ClientStats{})
		s := val.(*ClientStats)
		if loaded {
			old := atomic.LoadInt64(&s.Requests)
			if atomic.CompareAndSwapInt64(&s.Requests, old, old+1) {
				return
			}
		} else {
			atomic.AddInt64(&s.Requests, 1)
			return
		}
	}
}

// AddClientBytes 增加客户端类型的流量统计
func (sc *StatsCollector) AddClientBytes(clientType string, bytes int) {
	val, _ := sc.clients.LoadOrStore(clientType, &ClientStats{})
	s := val.(*ClientStats)
	atomic.AddInt64(&s.Bytes, int64(bytes))
}

// IncrementUpstream 增加上游主机计数
func (sc *StatsCollector) IncrementUpstream(upstream string) {
	sc.incrementMapCounter(&sc.upstreams, upstream)
}

// IncrementImage 增加镜像计数
func (sc *StatsCollector) IncrementImage(imageName string) {
	if imageName == "" {
		return
	}
	sc.incrementMapCounter(&sc.images, imageName)
}

// IncrementClientIP 增加客户端 IP 统计（请求+流量）
func (sc *StatsCollector) IncrementClientIP(ip string) {
	if ip == "" {
		return
	}
	for {
		val, loaded := sc.clientIPs.LoadOrStore(ip, &ClientStats{})
		s := val.(*ClientStats)
		if loaded {
			old := atomic.LoadInt64(&s.Requests)
			if atomic.CompareAndSwapInt64(&s.Requests, old, old+1) {
				return
			}
		} else {
			atomic.AddInt64(&s.Requests, 1)
			return
		}
	}
}

// AddClientIPBytes 增加客户端 IP 的流量统计
func (sc *StatsCollector) AddClientIPBytes(ip string, bytes int) {
	if ip == "" {
		return
	}
	val, _ := sc.clientIPs.LoadOrStore(ip, &ClientStats{})
	s := val.(*ClientStats)
	atomic.AddInt64(&s.Bytes, int64(bytes))
}

// AddBytesReceived 增加接收字节数（从上游下载的流量）
func (sc *StatsCollector) AddBytesReceived(bytes int) {
	atomic.AddInt64(&sc.bytesReceived, int64(bytes))
}

// IncrementActiveConns 增加活跃连接数
func (sc *StatsCollector) IncrementActiveConns() {
	atomic.AddInt64(&sc.activeConns, 1)
}

// DecrementActiveConns 减少活跃连接数
func (sc *StatsCollector) DecrementActiveConns() {
	atomic.AddInt64(&sc.activeConns, -1)
}

const rateWindowNano = int64(time.Second)

// AddBytesWithRate 增加发送字节数并更新速率统计
func (sc *StatsCollector) AddBytesWithRate(bytes int) {
	atomic.AddInt64(&sc.bytesSent, int64(bytes))

	now := time.Now().UnixNano()

	sc.rateMutex.Lock()
	windowStart := sc.rateWindowStart

	if windowStart == 0 || now-windowStart > rateWindowNano {
		sc.rateWindowStart = now
		sc.bytesRateWindow = int64(bytes)
		sc.rateMutex.Unlock()
		return
	}

	sc.bytesRateWindow += int64(bytes)
	sc.rateMutex.Unlock()
}

// GetActiveConns 获取当前活跃连接数
func (sc *StatsCollector) GetActiveConns() int64 {
	return atomic.LoadInt64(&sc.activeConns)
}

// GetBytesRate 获取当前传输速率（字节/秒）
func (sc *StatsCollector) GetBytesRate() int64 {
	now := time.Now().UnixNano()

	sc.rateMutex.Lock()
	windowStart := sc.rateWindowStart
	bytesInWindow := sc.bytesRateWindow
	sc.rateMutex.Unlock()

	if windowStart == 0 {
		return 0
	}

	elapsed := now - windowStart
	if elapsed <= 0 || elapsed > rateWindowNano {
		return 0
	}

	return bytesInWindow * int64(time.Second) / elapsed
}

// GetStats 获取统计数据
func (sc *StatsCollector) GetStats() map[string]any {
	uptime := time.Since(sc.startTime)

	// 收集 clients
	clients := make(map[string]ClientStats)
	sc.clients.Range(func(key, value any) bool {
		s := value.(*ClientStats)
		clients[key.(string)] = ClientStats{
			Requests: atomic.LoadInt64(&s.Requests),
			Bytes:    atomic.LoadInt64(&s.Bytes),
		}
		return true
	})

	// 收集 upstreams
	upstreams := make(map[string]int64)
	sc.upstreams.Range(func(key, value any) bool {
		upstreams[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})

	// 收集 images
	images := make(map[string]int64)
	sc.images.Range(func(key, value any) bool {
		images[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})

	// 收集 clientIPs
	clientIPs := make(map[string]ClientStats)
	sc.clientIPs.Range(func(key, value any) bool {
		s := value.(*ClientStats)
		clientIPs[key.(string)] = ClientStats{
			Requests: atomic.LoadInt64(&s.Requests),
			Bytes:    atomic.LoadInt64(&s.Bytes),
		}
		return true
	})

	return map[string]any{
		"totalRequests": atomic.LoadInt64(&sc.totalRequests),
		"cacheHits":     atomic.LoadInt64(&sc.cacheHits),
		"cacheMisses":   atomic.LoadInt64(&sc.cacheMisses),
		"uptime":        uptime.Seconds(),
		"clients":       clients,
		"upstreams":     upstreams,
		"images":        images,
		"clientIPs":     clientIPs,
		"bytesSent":     atomic.LoadInt64(&sc.bytesSent),
		"bytesReceived": atomic.LoadInt64(&sc.bytesReceived),
		"activeConns":   atomic.LoadInt64(&sc.activeConns),
		"bytesRate":     sc.GetBytesRate(),
	}
}
