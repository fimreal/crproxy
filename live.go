//go:build !lite
// +build !lite

package main

import (
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================ 速率表 ============================

// rateBucket 一个等宽统计桶。
type rateBucket struct {
	start time.Time
	tx    int64
	rx    int64
}

// rateMeter 滑动窗口速率表。
//
// 旧实现只有一个 1 秒窗口，而且只在请求结束时记账，结果是：长下载期间速率
// 恒为 0，请求刚结束时冒一个尖峰，一秒后立刻掉回 0，5 秒轮询基本抓不到。
// 这里改为「N 个等宽桶 + 环形推进」：字节在流经数据路径时就记进去，速率按
// 窗口内实际覆盖的时长计算，流量停止后随窗口自然衰减。
type rateMeter struct {
	mu      sync.Mutex
	buckets []rateBucket
	idx     int
	step    time.Duration
	window  time.Duration
}

func newRateMeter(count int, step time.Duration) *rateMeter {
	m := &rateMeter{
		buckets: make([]rateBucket, count),
		step:    step,
		window:  time.Duration(count) * step,
	}
	now := time.Now()
	for i := range m.buckets {
		m.buckets[i].start = now
	}
	return m
}

// advance 把窗口推进到 now，顺带清空过期桶。调用方需持有 m.mu。
func (m *rateMeter) advance(now time.Time) {
	if now.Sub(m.buckets[m.idx].start) >= m.window {
		// 空闲超过一整个窗口，直接整窗重置，不必逐个桶追赶
		for i := range m.buckets {
			m.buckets[i] = rateBucket{start: now}
		}
		m.idx = 0
		return
	}
	for now.Sub(m.buckets[m.idx].start) >= m.step {
		next := (m.idx + 1) % len(m.buckets)
		m.buckets[next] = rateBucket{start: m.buckets[m.idx].start.Add(m.step)}
		m.idx = next
	}
}

func (m *rateMeter) add(tx, rx int64) {
	if tx == 0 && rx == 0 {
		return
	}
	m.mu.Lock()
	m.advance(time.Now())
	m.buckets[m.idx].tx += tx
	m.buckets[m.idx].rx += rx
	m.mu.Unlock()
}

// rates 返回窗口内的平均速率（字节/秒）。
func (m *rateMeter) rates() (tx float64, rx float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.advance(now)

	var sumTx, sumRx int64
	var oldest time.Time
	for _, b := range m.buckets {
		if b.tx == 0 && b.rx == 0 {
			continue
		}
		sumTx += b.tx
		sumRx += b.rx
		if oldest.IsZero() || b.start.Before(oldest) {
			oldest = b.start
		}
	}
	if oldest.IsZero() {
		return 0, 0
	}

	span := now.Sub(oldest).Seconds()
	if span < m.step.Seconds() {
		span = m.step.Seconds()
	}
	if span > m.window.Seconds() {
		span = m.window.Seconds()
	}
	return float64(sumTx) / span, float64(sumRx) / span
}

func (m *rateMeter) windowSeconds() float64 {
	return m.window.Seconds()
}

// ============================ 任务模型 ============================

const (
	// liveTaskCtxKey 任务在 gin.Context 中的键
	liveTaskCtxKey = "liveTask"
	// liveBucketCount/liveBucketWidth 决定速率窗口：12 × 500ms = 6 秒
	liveBucketCount = 12
	liveBucketWidth = 500 * time.Millisecond
	// liveHistoryLimit 保留的已完成任务条数
	liveHistoryLimit = 300
	// liveSnapshotHistory 单次快照下发的历史条数
	liveSnapshotHistory = 60
	// liveMapLimit 聚合表（镜像/IP）最大条目数，防止长期运行内存膨胀
	liveMapLimit = 500
	// liveAggTTL 聚合条目在「无活跃请求」前提下的保留时长。
	// 没有它的话，表一旦满了新客户端/新镜像就永远进不来（旧条目只进不出）。
	liveAggTTL = 10 * time.Minute
)

// liveTask 一次正在进行（或刚结束）的代理请求。
type liveTask struct {
	ID         string
	ClientIP   string
	ClientType string
	Method     string
	Image      string
	Kind       string
	Reference  string
	StartAt    time.Time
	// aggClient/aggIP 分别表示该任务是否成功登记进对应的聚合表。
	// 两张表必须独立记录：任一张表满员都不能影响另一张的结算。
	aggClient bool
	aggIP     bool

	mu       sync.Mutex
	upstream string
	status   int
	cache    string
	finished bool
	endAt    time.Time

	total atomic.Int64
	sent  atomic.Int64
	recv  atomic.Int64
}

func (t *liveTask) addSent(n int64) {
	t.sent.Add(n)
	liveRate.add(n, 0)
	// 会话总量也实时累加，否则大文件传输期间会出现「速率很高、总量为 0」
	live.totalSent.Add(n)
}

func (t *liveTask) addRecv(n int64) {
	t.recv.Add(n)
	liveRate.add(0, n)
	live.totalRecv.Add(n)
}

func (t *liveTask) setTotal(n int64) {
	if n > 0 {
		t.total.Store(n)
	}
}

func (t *liveTask) setUpstream(up string) {
	if up == "" {
		return
	}
	t.mu.Lock()
	t.upstream = up
	t.mu.Unlock()
}

func (t *liveTask) setStatus(status int) {
	t.mu.Lock()
	t.status = status
	t.mu.Unlock()
}

func (t *liveTask) setCache(state string) {
	t.mu.Lock()
	t.cache = state
	t.mu.Unlock()
}

// claimFinish 抢占式地把任务标记为已结算，返回 false 表示它已经结算过。
// 结算路径有两条（正常收尾 + defer 兜底），必须保证只有一条真正生效。
func (t *liveTask) claimFinish() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.finished {
		return false
	}
	t.finished = true
	t.endAt = time.Now()
	return true
}

// size 返回本次任务实际发给客户端的字节数。
func (t *liveTask) size() int64 {
	return t.sent.Load()
}

// recvBytes 返回本次任务实际从上游读到的字节数。
func (t *liveTask) recvBytes() int64 {
	return t.recv.Load()
}

// liveTaskView 是任务对外（JSON）的只读视图。
type liveTaskView struct {
	ID         string  `json:"id"`
	ClientIP   string  `json:"clientIp"`
	ClientType string  `json:"clientType"`
	Method     string  `json:"method"`
	Kind       string  `json:"kind"`
	Image      string  `json:"image"`
	Reference  string  `json:"reference"`
	Upstream   string  `json:"upstream"`
	Status     int     `json:"status"`
	Cache      string  `json:"cache"`
	Total      int64   `json:"total"`
	Sent       int64   `json:"sent"`
	Recv       int64   `json:"recv"`
	Progress   float64 `json:"progress"`
	Speed      float64 `json:"speed"`
	Elapsed    float64 `json:"elapsed"`
	Finished   bool    `json:"finished"`
	StartedAt  int64   `json:"startedAt"`
}

func (t *liveTask) snapshot() liveTaskView {
	t.mu.Lock()
	upstream, status, cache, finished, endAt := t.upstream, t.status, t.cache, t.finished, t.endAt
	t.mu.Unlock()

	sent := t.sent.Load()
	recv := t.recv.Load()
	total := t.total.Load()

	end := time.Now()
	if finished && !endAt.IsZero() {
		end = endAt
	}
	elapsed := end.Sub(t.StartAt).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}

	view := liveTaskView{
		ID:         t.ID,
		ClientIP:   t.ClientIP,
		ClientType: t.ClientType,
		Method:     t.Method,
		Kind:       t.Kind,
		Image:      t.Image,
		Reference:  t.Reference,
		Upstream:   upstream,
		Status:     status,
		Cache:      cache,
		Total:      total,
		Sent:       sent,
		Recv:       recv,
		Elapsed:    elapsed,
		Finished:   finished,
		StartedAt:  t.StartAt.UnixMilli(),
	}
	if total > 0 {
		view.Progress = float64(sent) / float64(total)
		if view.Progress > 1 {
			view.Progress = 1
		}
	}
	// 耗时过短（如 1ms 内的 manifest 请求）算速度没有意义，直接留 0
	if elapsed > 0.01 {
		view.Speed = float64(sent) / elapsed
	}
	return view
}

// liveAgg 会话内聚合（按客户端类型 / 按镜像 / 按客户端 IP）。
type liveAgg struct {
	Type     string
	Requests int64
	Bytes    int64
	Active   int64
	LastSeen time.Time
}

// addType 记录该条目出现过的客户端类型。同一个 IP 可能用多种客户端拉取，
// 所以这里做去重拼接（最多展示 4 种）。
func (a *liveAgg) addType(t string) {
	if t == "" || a.Type == t {
		return
	}
	if a.Type == "" {
		a.Type = t
		return
	}
	for _, part := range strings.Split(a.Type, ", ") {
		if part == t {
			return
		}
	}
	if strings.Count(a.Type, ",") >= 3 {
		return
	}
	a.Type += ", " + t
}

type liveAggView struct {
	Type     string `json:"type,omitempty"`
	Key      string `json:"key"`
	Requests int64  `json:"requests"`
	Bytes    int64  `json:"bytes"`
	Active   int64  `json:"active"`
	LastSeen int64  `json:"lastSeen"`
}

// ============================ 采集器 ============================

// LiveTracker 实时任务与聚合指标的采集器。
type LiveTracker struct {
	mu      sync.RWMutex
	startAt time.Time
	active  map[string]*liveTask
	history []*liveTask
	clients map[string]*liveAgg
	ips     map[string]*liveAgg
	images  map[string]*liveAgg

	totalRequests atomic.Int64
	totalSent     atomic.Int64
	totalRecv     atomic.Int64
	cacheHits     atomic.Int64
	cacheMisses   atomic.Int64
}

var (
	live     = newLiveTracker()
	liveRate = newRateMeter(liveBucketCount, liveBucketWidth)
)

func newLiveTracker() *LiveTracker {
	return &LiveTracker{
		startAt: time.Now(),
		active:  make(map[string]*liveTask),
		clients: make(map[string]*liveAgg),
		ips:     make(map[string]*liveAgg),
		images:  make(map[string]*liveAgg),
	}
}

func liveTaskID(c *gin.Context) string {
	if v, ok := c.Get("requestID"); ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return generateRequestID()
}

// Begin 为一次代理请求登记实时任务。
func (lt *LiveTracker) Begin(c *gin.Context) *liveTask {
	path := c.Request.URL.Path
	kind, reference := classifyLiveRequest(path)

	image := parseImageName(path)
	if image == "" && kind == "token" {
		// /token/ 请求的镜像藏在 scope=repository:library/alpine:pull 里
		image = parseImageFromScope(c.Request.URL.RawQuery)
	}

	t := &liveTask{
		ID:         liveTaskID(c),
		ClientIP:   c.ClientIP(),
		ClientType: parseClientType(c.GetHeader("User-Agent")),
		Method:     c.Request.Method,
		Image:      image,
		Kind:       kind,
		Reference:  reference,
		StartAt:    time.Now(),
	}

	lt.mu.Lock()
	lt.active[t.ID] = t
	// 两张聚合表必须分别登记：若写成 A && B，IP 表达到上限时会短路掉
	// 客户端表的结算，导致 clients 表的 Active 只增不减。
	t.aggClient = lt.aggBeginLocked(lt.clients, t.ClientType, t.ClientType)
	t.aggIP = lt.aggBeginLocked(lt.ips, t.ClientIP, t.ClientType)
	if image != "" {
		lt.aggBeginLocked(lt.images, image, "")
	}
	lt.mu.Unlock()

	lt.totalRequests.Add(1)
	c.Set(liveTaskCtxKey, t)
	return t
}

// Finish 结算任务：落历史、更新聚合。
func (lt *LiveTracker) Finish(c *gin.Context, status int) *liveTask {
	v, ok := c.Get(liveTaskCtxKey)
	if !ok {
		return nil
	}
	t, ok := v.(*liveTask)
	if !ok {
		return nil
	}

	if up, ok := c.Get("upstreamHost"); ok {
		if s, ok := up.(string); ok {
			t.setUpstream(s)
		}
	}
	t.setStatus(status)
	state := cacheStateOf(c)
	t.setCache(state)
	if !t.claimFinish() {
		// 已经结算过（defer 兜底与正常收尾重入），不能重复计入历史与聚合
		return nil
	}

	sent := t.sent.Load()
	switch state {
	case "HIT":
		lt.cacheHits.Add(1)
	case "MISS":
		lt.cacheMisses.Add(1)
	}

	lt.mu.Lock()
	delete(lt.active, t.ID)
	lt.history = append(lt.history, t)
	if len(lt.history) > liveHistoryLimit {
		// 就地保留最近 liveHistoryLimit 条：copy 复用底层数组，
		// 避免每个请求都重新分配一个 300 元素切片
		n := copy(lt.history, lt.history[len(lt.history)-liveHistoryLimit:])
		lt.history = lt.history[:n]
	}
	if t.aggClient {
		lt.aggEndLocked(lt.clients, t.ClientType, sent)
	}
	if t.aggIP {
		lt.aggEndLocked(lt.ips, t.ClientIP, sent)
	}
	if t.Image != "" {
		lt.aggEndLocked(lt.images, t.Image, sent)
	}
	lt.mu.Unlock()

	return t
}

// aggBeginLocked 登记一次聚合请求。返回 false 表示该表已满、本次不参与聚合。
func (lt *LiveTracker) aggBeginLocked(m map[string]*liveAgg, key, kind string) bool {
	if key == "" {
		return false
	}
	a, ok := m[key]
	if !ok {
		if len(m) >= liveMapLimit {
			// 表满：先淘汰长期空闲的条目；腾不出位置才放弃本次登记
			evictIdleAggLocked(m, time.Now())
			if len(m) >= liveMapLimit {
				return false
			}
		}
		a = &liveAgg{}
		m[key] = a
	}
	a.addType(kind)
	a.Requests++
	a.Active++
	a.LastSeen = time.Now()
	return true
}

// evictIdleAggLocked 淘汰「当前无活跃请求」且空闲超过 liveAggTTL 的条目。
// 调用方需持有 lt.mu 写锁。
func evictIdleAggLocked(m map[string]*liveAgg, now time.Time) {
	for k, a := range m {
		if a.Active == 0 && now.Sub(a.LastSeen) > liveAggTTL {
			delete(m, k)
		}
	}
}

// sweepIdleAgg 仅在聚合表触达容量上限时做一次淘汰，避免 1 秒一次的轮询
// 都去抢写锁。这样即使没有新请求进来，面板里的过期条目也会被清掉。
func (lt *LiveTracker) sweepIdleAgg() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	now := time.Now()
	for _, m := range [...]map[string]*liveAgg{lt.clients, lt.ips, lt.images} {
		if len(m) >= liveMapLimit {
			evictIdleAggLocked(m, now)
		}
	}
}

func (lt *LiveTracker) aggEndLocked(m map[string]*liveAgg, key string, bytes int64) {
	if a, ok := m[key]; ok {
		a.Bytes += bytes
		a.Active--
		if a.Active < 0 {
			a.Active = 0
		}
		a.LastSeen = time.Now()
	}
}

// ---- 快照 ----

type liveRateView struct {
	TX        float64 `json:"tx"`
	RX        float64 `json:"rx"`
	WindowSec float64 `json:"windowSec"`
}

type liveTotalsView struct {
	TX          int64 `json:"tx"`
	RX          int64 `json:"rx"`
	Requests    int64 `json:"requests"`
	Active      int   `json:"active"`
	CacheHits   int64 `json:"cacheHits"`
	CacheMisses int64 `json:"cacheMisses"`
}

type liveSnapshot struct {
	Uptime      float64        `json:"uptime"`
	Rate        liveRateView   `json:"rate"`
	Totals      liveTotalsView `json:"totals"`
	ActiveTasks []liveTaskView `json:"activeTasks"`
	RecentTasks []liveTaskView `json:"recentTasks"`
	Clients     []liveAggView  `json:"clients"`
	ClientIPs   []liveAggView  `json:"clientIps"`
	Images      []liveAggView  `json:"images"`
}

// Snapshot 输出当前实时状态。
func (lt *LiveTracker) Snapshot() liveSnapshot {
	tx, rx := liveRate.rates()
	lt.sweepIdleAgg()

	lt.mu.RLock()
	active := make([]liveTaskView, 0, len(lt.active))
	// 进行中的任务还没结算进聚合表，先按在途字节补上，
	// 否则边下边看的统计里镜像/客户端流量会一直是 0
	pendingClients := make(map[string]int64, len(lt.active))
	pendingIPs := make(map[string]int64, len(lt.active))
	pendingImages := make(map[string]int64, len(lt.active))
	for _, t := range lt.active {
		active = append(active, t.snapshot())
		sent := t.sent.Load()
		if t.aggClient {
			pendingClients[t.ClientType] += sent
		}
		if t.aggIP {
			pendingIPs[t.ClientIP] += sent
		}
		if t.Image != "" {
			pendingImages[t.Image] += sent
		}
	}
	recent := make([]liveTaskView, 0, liveSnapshotHistory)
	for i := len(lt.history) - 1; i >= 0 && len(recent) < liveSnapshotHistory; i-- {
		recent = append(recent, lt.history[i].snapshot())
	}
	clients := collectAgg(lt.clients, pendingClients, 50)
	ips := collectAgg(lt.ips, pendingIPs, 20)
	images := collectAgg(lt.images, pendingImages, 50)
	lt.mu.RUnlock()

	// 正在下载的排前面，其余按开始时间倒序
	sort.SliceStable(active, func(i, j int) bool {
		return active[i].StartedAt > active[j].StartedAt
	})

	return liveSnapshot{
		Uptime: time.Since(lt.startAt).Seconds(),
		Rate: liveRateView{
			TX:        tx,
			RX:        rx,
			WindowSec: liveRate.windowSeconds(),
		},
		Totals: liveTotalsView{
			TX:          lt.totalSent.Load(),
			RX:          lt.totalRecv.Load(),
			Requests:    lt.totalRequests.Load(),
			Active:      len(active),
			CacheHits:   lt.cacheHits.Load(),
			CacheMisses: lt.cacheMisses.Load(),
		},
		ActiveTasks: active,
		RecentTasks: recent,
		Clients:     clients,
		ClientIPs:   ips,
		Images:      images,
	}
}

// collectAgg 汇总聚合表，并把在途任务的字节数合并进来。
func collectAgg(m map[string]*liveAgg, pending map[string]int64, limit int) []liveAggView {
	out := make([]liveAggView, 0, len(m))
	for k, a := range m {
		out = append(out, liveAggView{
			Type:     a.Type,
			Key:      k,
			Requests: a.Requests,
			Bytes:    a.Bytes + pending[k],
			Active:   a.Active,
			LastSeen: a.LastSeen.UnixMilli(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active > out[j].Active
		}
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Requests > out[j].Requests
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ============================ 数据路径挂钩 ============================

// liveWriter 在字节真正写给客户端时实时记账。
type liveWriter struct {
	gin.ResponseWriter
	task *liveTask
}

func (w *liveWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.task.addSent(int64(n))
	}
	return n, err
}

func (w *liveWriter) WriteString(s string) (int, error) {
	n, err := w.ResponseWriter.WriteString(s)
	if n > 0 {
		w.task.addSent(int64(n))
	}
	return n, err
}

// liveReadCloser 在从上游读取字节时实时记账。
type liveReadCloser struct {
	io.ReadCloser
	task *liveTask
}

func (r *liveReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.task.addRecv(int64(n))
	}
	return n, err
}

func init() {
	metricAttachWriter = attachLiveWriter
	metricWrapUpstream = wrapLiveUpstream
	metricNoteTotal = noteLiveTotal
}

func noteLiveTotal(c *gin.Context, total int64) {
	if t := liveTaskOf(c); t != nil {
		t.setTotal(total)
	}
}

// liveTaskOf 从上下文取回本次请求的实时任务。
func liveTaskOf(c *gin.Context) *liveTask {
	v, ok := c.Get(liveTaskCtxKey)
	if !ok {
		return nil
	}
	t, ok := v.(*liveTask)
	if !ok {
		return nil
	}
	return t
}

func attachLiveWriter(c *gin.Context) {
	t := liveTaskOf(c)
	if t == nil {
		return
	}
	if _, already := c.Writer.(*liveWriter); already {
		return
	}
	c.Writer = &liveWriter{ResponseWriter: c.Writer, task: t}
}

func wrapLiveUpstream(c *gin.Context, resp *http.Response) {
	t := liveTaskOf(c)
	if t == nil {
		return
	}
	if resp.ContentLength > 0 {
		t.setTotal(resp.ContentLength)
	}
	resp.Body = &liveReadCloser{ReadCloser: resp.Body, task: t}
}

// ============================ 解析辅助 ============================

// cacheStateOf 读取本次请求的缓存命中状态。
func cacheStateOf(c *gin.Context) string {
	if s := c.Writer.Header().Get("X-Cache"); s != "" {
		return s
	}
	return "BYPASS"
}

// classifyLiveRequest 从请求路径解析操作类型和引用（tag/digest）。
func classifyLiveRequest(path string) (kind, reference string) {
	switch {
	case strings.HasPrefix(path, "/v2/"):
	case strings.HasPrefix(path, "/token/"):
		return "token", ""
	default:
		return "other", ""
	}

	rest := strings.TrimPrefix(path, "/v2/")
	switch {
	case rest == "":
		return "api", ""
	case strings.Contains(rest, "/manifests/"):
		return "manifest", tailAfter(rest, "/manifests/")
	case strings.Contains(rest, "/blobs/uploads/"):
		return "upload", ""
	case strings.Contains(rest, "/blobs/"):
		return "blob", tailAfter(rest, "/blobs/")
	case strings.HasSuffix(rest, "/tags/list"):
		return "taglist", ""
	}
	return "other", ""
}

func tailAfter(s, delim string) string {
	i := strings.LastIndex(s, delim)
	if i < 0 {
		return ""
	}
	out := s[i+len(delim):]
	if j := strings.IndexByte(out, '?'); j >= 0 {
		out = out[:j]
	}
	return strings.Trim(out, "/")
}

// parseImageFromScope 从 token 请求的 scope=repository:<name>:pull 中取镜像名。
func parseImageFromScope(rawQuery string) string {
	for _, kv := range strings.Split(rawQuery, "&") {
		key, value, found := strings.Cut(kv, "=")
		if !found || key != "scope" {
			continue
		}
		value, err := url.QueryUnescape(value)
		if err != nil {
			continue
		}
		if rest, ok := strings.CutPrefix(value, "repository:"); ok {
			if idx := strings.LastIndex(rest, ":"); idx > 0 {
				rest = rest[:idx]
			}
			if len(rest) > 100 {
				rest = rest[:100]
			}
			return rest
		}
	}
	return ""
}
