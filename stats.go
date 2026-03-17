package main

import "sync/atomic"

// StatsCollector 统计收集器
type StatsCollector struct {
	totalRequests int64
	cacheHits     int64
	cacheMisses   int64
}

// NewStatsCollector 创建统计收集器
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{}
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

// GetStats 获取统计数据
func (sc *StatsCollector) GetStats() map[string]int64 {
	return map[string]int64{
		"totalRequests": atomic.LoadInt64(&sc.totalRequests),
		"cacheHits":     atomic.LoadInt64(&sc.cacheHits),
		"cacheMisses":   atomic.LoadInt64(&sc.cacheMisses),
	}
}
