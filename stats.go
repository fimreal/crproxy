//go:build !lite
// +build !lite

package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// StatsCollector 统计收集器
type StatsCollector struct {
	totalRequests int64
	cacheHits     int64
	cacheMisses   int64
	startTime     time.Time
	clients       sync.Map // map[string]int64 - client type -> count
	upstreams     sync.Map // map[string]int64 - upstream host -> count
	images        sync.Map // map[string]int64 - image name -> count
	clientIPs     sync.Map // map[string]int64 - client IP -> count
	bytesSent     int64    // 上传流量（发送给客户端）
	bytesReceived int64    // 下载流量（从上游接收）
}

// NewStatsCollector 创建统计收集器
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		startTime: time.Now(),
	}
}

// parseClientType 从 User-Agent 解析客户端类型
func parseClientType(userAgent string) string {
	if userAgent == "" {
		return "unknown"
	}
	ua := strings.ToLower(userAgent)

	// Docker: docker/24.0.0, docker/1.41 (windows)
	if strings.Contains(ua, "docker") {
		return "docker"
	}
	// Podman: libpod/4.0.0, podman/4.0.0
	if strings.Contains(ua, "podman") || strings.Contains(ua, "libpod") {
		return "podman"
	}
	// containerd: containerd/1.6.0
	if strings.Contains(ua, "containerd") {
		return "containerd"
	}
	// crane: crane (gcrane)
	if strings.Contains(ua, "crane") {
		return "crane"
	}
	// skopeo: skopeo/1.9.0
	if strings.Contains(ua, "skopeo") {
		return "skopeo"
	}
	// buildah: buildah/1.27.0
	if strings.Contains(ua, "buildah") {
		return "buildah"
	}
	// nerdctl: nerdctl/0.22.0
	if strings.Contains(ua, "nerdctl") {
		return "nerdctl"
	}
	// Go http client: Go-http-client/1.1
	if strings.Contains(ua, "go-http-client") {
		return "go-http-client"
	}
	// Python requests: python-requests/2.28.0
	if strings.Contains(ua, "python-requests") {
		return "python-requests"
	}
	// curl: curl/7.81.0
	if strings.Contains(ua, "curl") {
		return "curl"
	}
	// wget: wget/1.21
	if strings.Contains(ua, "wget") {
		return "wget"
	}
	// Harbor replication: harbor-scanner, harbor-registry
	if strings.Contains(ua, "harbor") {
		return "harbor"
	}
	// AWS ECR: aws-sdk-go
	if strings.Contains(ua, "aws-sdk") {
		return "aws-sdk"
	}

	return "other"
}

// parseImageName 从请求路径解析镜像名称
// 例如: /v2/library/alpine/manifests/latest -> library/alpine
// 例如: /v2/ghcr.io/nginx/manifests/v1 -> ghcr.io/nginx (if domain-suffix mode)
func parseImageName(path string) string {
	// 路径格式: /v2/<name>/manifests/<ref> 或 /v2/<name>/blobs/<digest>
	if !strings.HasPrefix(path, "/v2/") {
		return ""
	}

	path = strings.TrimPrefix(path, "/v2/")

	// 查找 /manifests/ 或 /blobs/ 或 /tags/ 或 /blobs/uploads/
	delimiters := []string{"/manifests/", "/blobs/", "/tags/", "/blobs/uploads/"}
	for _, delim := range delimiters {
		if idx := strings.Index(path, delim); idx > 0 {
			imageName := path[:idx]
			// 限制长度，避免统计太长的名字
			if len(imageName) > 100 {
				imageName = imageName[:100]
			}
			return imageName
		}
	}

	// 如果没有找到分隔符，可能是 catalog 或其他 API
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

// incrementMapCounter 通用的 map 计数器
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

// IncrementClient 增加客户端类型计数
func (sc *StatsCollector) IncrementClient(clientType string) {
	sc.incrementMapCounter(&sc.clients, clientType)
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

// IncrementClientIP 增加客户端 IP 计数
func (sc *StatsCollector) IncrementClientIP(ip string) {
	if ip == "" {
		return
	}
	sc.incrementMapCounter(&sc.clientIPs, ip)
}

// AddBytesSent 增加发送字节数
func (sc *StatsCollector) AddBytesSent(bytes int) {
	atomic.AddInt64(&sc.bytesSent, int64(bytes))
}

// AddBytesReceived 增加接收字节数
func (sc *StatsCollector) AddBytesReceived(bytes int) {
	atomic.AddInt64(&sc.bytesReceived, int64(bytes))
}

// GetStats 获取统计数据
func (sc *StatsCollector) GetStats() map[string]interface{} {
	uptime := time.Since(sc.startTime)

	// 收集客户端统计
	clients := make(map[string]int64)
	sc.clients.Range(func(key, value interface{}) bool {
		clients[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})

	// 收集上游统计
	upstreams := make(map[string]int64)
	sc.upstreams.Range(func(key, value interface{}) bool {
		upstreams[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})

	// 收集镜像统计
	images := make(map[string]int64)
	sc.images.Range(func(key, value interface{}) bool {
		images[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})

	// 收集客户端 IP 统计
	clientIPs := make(map[string]int64)
	sc.clientIPs.Range(func(key, value interface{}) bool {
		clientIPs[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})

	return map[string]interface{}{
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
	}
}
