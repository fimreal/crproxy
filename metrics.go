package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// 实时指标采集钩子。
//
// 这些函数被 proxy.go / cache.go 这类「完整版与 lite 版共用」的文件调用，
// 默认实现是空操作，因此 lite 构建不会为统计付出任何代价；
// 完整版由 live.go 的 init() 替换为真实实现。
var (
	// metricAttachWriter 把当前 ResponseWriter 换成会实时记账的包装器。
	// 必须在任何字节写入之前调用。
	metricAttachWriter = func(c *gin.Context) {}

	// metricWrapUpstream 包装上游响应体，用于实时统计下行（RX）流量，
	// 并顺便记录响应体总长度。
	metricWrapUpstream = func(c *gin.Context, resp *http.Response) {}

	// metricNoteTotal 记录响应体总长度。命中本地缓存时没有上游响应，
	// 需要单独告知总长度，否则进度条无法计算。
	metricNoteTotal = func(c *gin.Context, total int64) {}
)
