//go:build !lite
// +build !lite

package main

import (
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// newTestContext 构造一个走代理路径的 gin 上下文（可指定 UA）。
func newTestContext(method, target, ua string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(method, target, nil)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	c.Request = req
	return c
}

// 未挂载 liveWriter 的代理请求（如 token 直答）：任务照样登记并结算，
// 字节数回落到 gin 自己记的 c.Writer.Size()。
func TestLiveFallsBackToWriterSize(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sc := NewStatsCollector()
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestIDMiddleware())
	r.Use(accessLogMiddleware(sc))
	r.GET("/v2/library/alpine/blobs/sha256:aaa", func(c *gin.Context) {
		c.String(200, "hello")
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/v2/library/alpine/blobs/sha256:aaa", nil))

	if got := sc.GetActiveConns(); got != 0 {
		t.Errorf("activeConns = %d, want 0", got)
	}
	snapshot := live.Snapshot()
	if snapshot.Totals.Active != 0 {
		t.Errorf("实时活跃任务 = %d, want 0", snapshot.Totals.Active)
	}
	if got := sc.GetStats()["bytesSent"]; got != int64(5) {
		t.Errorf("统计发送字节 = %v, want 5（未挂载 liveWriter 时的兜底）", got)
	}

	found := findRecentByImage(snapshot, "library/alpine")
	if found == nil {
		t.Fatal("最近完成任务里找不到本次请求")
	}
	if found.Kind != "blob" || found.Status != 200 || !found.Finished {
		t.Errorf("任务视图异常: kind=%q status=%d finished=%v", found.Kind, found.Status, found.Finished)
	}
}

// 挂载 liveWriter 后（正常 blob 下载路径），任务记录的是实测字节数。
func TestLiveMeasuresStreamedBytes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sc := NewStatsCollector()
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestIDMiddleware())
	r.Use(accessLogMiddleware(sc))
	r.GET("/v2/library/busybox/blobs/sha256:eee", func(c *gin.Context) {
		metricAttachWriter(c) // forward() 里做的事
		c.Writer.WriteHeader(200)
		c.Writer.Write([]byte("0123456789"))
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/v2/library/busybox/blobs/sha256:eee", nil))

	found := findRecentByImage(live.Snapshot(), "library/busybox")
	if found == nil {
		t.Fatal("最近完成任务里找不到本次请求")
	}
	if found.Sent != 10 {
		t.Errorf("实测发送字节 = %d, want 10", found.Sent)
	}
	if got := sc.GetStats()["bytesSent"]; got != int64(10) {
		t.Errorf("统计发送字节 = %v, want 10", got)
	}
}

func findRecentByImage(snapshot liveSnapshot, image string) *liveTaskView {
	for i := range snapshot.RecentTasks {
		if snapshot.RecentTasks[i].Image == image {
			return &snapshot.RecentTasks[i]
		}
	}
	return nil
}

// 回归：IP 聚合表满员时，clients 聚合表的 Active 不能泄漏。
// （原实现用 `A && B` 登记两张表，B 失败会把 A 的结算一起短路掉。）
func TestLiveAggNoLeakWhenIPTableFull(t *testing.T) {
	lt := newLiveTracker()
	for i := 0; i < liveMapLimit; i++ {
		lt.aggBeginLocked(lt.ips, fmt.Sprintf("10.0.%d.%d", i/250, i%250), "docker")
	}
	if len(lt.ips) != liveMapLimit {
		t.Fatalf("准备失败：ips 表 = %d 条", len(lt.ips))
	}

	c := newTestContext("GET", "/v2/library/alpine/blobs/sha256:deadbeef", "docker/24.0.0")
	lt.Begin(c)
	task := liveTaskOf(c)
	if task == nil {
		t.Fatal("Begin 未登记任务")
	}
	if task.aggIP {
		t.Fatal("前置条件不符：IP 表已满且无空闲条目，aggIP 应为 false")
	}
	if !task.aggClient {
		t.Fatal("前置条件不符：客户端表未满，aggClient 应为 true")
	}
	if got := lt.clients["docker"].Active; got != 1 {
		t.Fatalf("Begin 后 clients.Active = %d, want 1", got)
	}
	task.addSent(1000)

	lt.Finish(c, 200)

	if got := lt.clients["docker"].Active; got != 0 {
		t.Errorf("clients.Active = %d, want 0（聚合计数泄漏）", got)
	}
	if got := lt.clients["docker"].Bytes; got != 1000 {
		t.Errorf("clients.Bytes = %d, want 1000", got)
	}
}

// 表满但条目都已空闲时，应淘汰它们给新客户端/新镜像腾位置。
func TestLiveAggEvictsIdleEntries(t *testing.T) {
	lt := newLiveTracker()
	for i := 0; i < liveMapLimit; i++ {
		lt.aggBeginLocked(lt.ips, fmt.Sprintf("10.2.%d.%d", i/250, i%250), "docker")
	}
	for _, a := range lt.ips {
		a.Active = 0 // 这些 IP 上的请求都已结束
		a.LastSeen = time.Now().Add(-2 * liveAggTTL)
	}

	c := newTestContext("GET", "/v2/library/redis/blobs/sha256:fff", "crane/0.20.0")
	c.Request.RemoteAddr = "192.168.9.9:1234"
	lt.Begin(c)
	task := liveTaskOf(c)
	if task == nil {
		t.Fatal("Begin 未登记任务")
	}
	if !task.aggIP {
		t.Error("空闲条目已被淘汰，新 IP 应能登记进聚合表")
	}
	if _, ok := lt.ips["192.168.9.9"]; !ok {
		t.Error("新 IP 未出现在聚合表中")
	}
	if len(lt.ips) >= liveMapLimit {
		t.Errorf("ips 表仍为 %d 条，空闲条目未被淘汰", len(lt.ips))
	}
}

// 有请求在途的条目不能被淘汰。
func TestLiveAggKeepsActiveEntries(t *testing.T) {
	lt := newLiveTracker()
	for i := 0; i < liveMapLimit; i++ {
		lt.aggBeginLocked(lt.ips, fmt.Sprintf("10.3.%d.%d", i/250, i%250), "docker")
	}
	for _, a := range lt.ips {
		a.LastSeen = time.Now().Add(-2 * liveAggTTL)
		a.Active = 1 // 模拟这些 IP 上仍有请求在途
	}

	c := newTestContext("GET", "/v2/library/nginx/blobs/sha256:aaa", "docker/24.0.0")
	c.Request.RemoteAddr = "192.168.9.10:1234"
	lt.Begin(c)
	if task := liveTaskOf(c); task == nil || task.aggIP {
		t.Error("在途条目不可淘汰，新 IP 本次应放弃登记")
	}
	if len(lt.ips) != liveMapLimit {
		t.Errorf("ips 表被误淘汰，剩余 %d 条", len(lt.ips))
	}
}

// 长时间没有新请求时，快照本身也应能把过期条目清掉。
func TestLiveSnapshotSweepsIdleAgg(t *testing.T) {
	lt := newLiveTracker()
	for i := 0; i < liveMapLimit; i++ {
		lt.aggBeginLocked(lt.ips, fmt.Sprintf("10.4.%d.%d", i/250, i%250), "docker")
	}
	for _, a := range lt.ips {
		a.Active = 0 // 请求都已结束，只剩过期数据
		a.LastSeen = time.Now().Add(-2 * liveAggTTL)
	}

	snapshot := lt.Snapshot()

	if len(lt.ips) != 0 {
		t.Errorf("快照后空闲条目应被清空，剩余 %d 条", len(lt.ips))
	}
	if len(snapshot.ClientIPs) != 0 {
		t.Errorf("快照不应再包含过期条目，实际 %d 条", len(snapshot.ClientIPs))
	}
}

// 回归：下游 handler panic 时，活跃连接数与实时任务都必须被结算。
// （清理逻辑若不用 defer，panic 会跳过它，计数只增不减、任务永久滞留。）
func TestLivePanicDoesNotLeak(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sc := NewStatsCollector()
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestIDMiddleware())
	r.Use(accessLogMiddleware(sc))
	r.GET("/v2/panic/blobs/sha256:bbb", func(c *gin.Context) {
		liveTaskOf(c).addSent(42) // 已经向客户端写过字节
		panic("boom")
	})

	before := live.Snapshot()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/v2/panic/blobs/sha256:bbb", nil))

	if got := sc.GetActiveConns(); got != 0 {
		t.Errorf("panic 后 activeConns = %d, want 0", got)
	}
	after := live.Snapshot()
	if after.Totals.Active != before.Totals.Active {
		t.Errorf("panic 后实时活跃任务 = %d, want %d（任务滞留）", after.Totals.Active, before.Totals.Active)
	}
	if len(after.RecentTasks) == 0 || after.RecentTasks[0].Sent != 42 {
		t.Errorf("panic 的任务未被结算落历史: %+v", after.RecentTasks[:min(1, len(after.RecentTasks))])
	}
}

// Finish 必须幂等：正常收尾与 defer 兜底都会调用它，缓存命中不能被记两次。
func TestLiveFinishIdempotent(t *testing.T) {
	lt := newLiveTracker()
	c := newTestContext("GET", "/v2/library/redis/blobs/sha256:ccc", "crane/0.20.0")
	c.Writer.Header().Set("X-Cache", "HIT")
	lt.Begin(c)

	if lt.Finish(c, 200) == nil {
		t.Fatal("首次 Finish 应返回任务")
	}
	if lt.Finish(c, 200) != nil {
		t.Error("重复 Finish 应返回 nil")
	}
	if got := lt.cacheHits.Load(); got != 1 {
		t.Errorf("cacheHits = %d, want 1（重复结算）", got)
	}
	if len(lt.history) != 1 {
		t.Errorf("history = %d 条, want 1", len(lt.history))
	}
	if got := lt.clients["crane"].Requests; got != 1 {
		t.Errorf("clients.Requests = %d, want 1", got)
	}
}

// 并发记账 + 并发快照：配合 -race 检验数据路径上的原子计数与锁。
func TestLiveConcurrentTracking(t *testing.T) {
	lt := newLiveTracker()
	const (
		workers = 24
		rounds  = 40
	)

	stop := make(chan struct{})
	var snapshotter sync.WaitGroup
	snapshotter.Add(1)
	go func() {
		defer snapshotter.Done()
		for {
			select {
			case <-stop:
				return
			default:
				lt.Snapshot()
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				ip := fmt.Sprintf("10.1.%d.%d", i, j)
				c := newTestContext("GET", "/v2/library/nginx/blobs/sha256:ddd", "skopeo/1.14")
				c.Request.RemoteAddr = ip + ":12345"
				task := lt.Begin(c)
				task.addSent(512)
				task.addRecv(512)
				lt.Finish(c, 200)
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	snapshotter.Wait()

	snapshot := lt.Snapshot()
	if snapshot.Totals.Active != 0 {
		t.Errorf("并发结束后活跃任务 = %d, want 0", snapshot.Totals.Active)
	}
	if snapshot.Totals.Requests != workers*rounds {
		t.Errorf("请求数 = %d, want %d", snapshot.Totals.Requests, workers*rounds)
	}
	if len(lt.history) > liveHistoryLimit {
		t.Errorf("history = %d 条, 超过上限 %d", len(lt.history), liveHistoryLimit)
	}
	if got := lt.clients["skopeo"].Active; got != 0 {
		t.Errorf("clients.Active = %d, want 0（并发下泄漏）", got)
	}
}

// 速率表：窗口内应有读数，长时间空闲后衰减为 0。
func TestRateMeterDecays(t *testing.T) {
	m := newRateMeter(4, 50*time.Millisecond) // 窗口 200ms
	m.add(1000, 500)

	tx, rx := m.rates()
	if tx <= 0 || rx <= 0 {
		t.Fatalf("窗口内速率应为正: tx=%v rx=%v", tx, rx)
	}

	time.Sleep(300 * time.Millisecond) // 超过整个窗口
	tx, rx = m.rates()
	if tx != 0 || rx != 0 {
		t.Errorf("空闲超窗口后速率应归零: tx=%v rx=%v", tx, rx)
	}
}

// 假死的 blob 任务（客户端消失、连接空闲超时尚未触发）不能计入在途下载：
// 它永远不会自己结束，算进去会让重启前的等待永久卡住。
func TestActiveDownloadsIgnoresStaleTasks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lt := newLiveTracker()

	live1 := lt.Begin(newTestContext("GET", "/v2/library/alpine/blobs/sha256:aaa", ""))
	zombie := lt.Begin(newTestContext("GET", "/v2/library/alpine/blobs/sha256:bbb", ""))
	if got := lt.ActiveDownloads(); got != 2 {
		t.Fatalf("初始在途下载 = %d, want 2", got)
	}

	live1.addSent(1) // 还在传字节
	zombie.lastMove.Store(time.Now().Add(-2 * downloadStaleIdle).UnixNano())

	if got := lt.ActiveDownloads(); got != 1 {
		t.Errorf("假死任务应被排除：在途下载 = %d, want 1", got)
	}
}
