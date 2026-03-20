//go:build !lite
// +build !lite

package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// generateContainerdHelp 生成 containerd 配置帮助信息
func generateContainerdHelp(c *gin.Context, domainSuffix string) {
	// 获取服务地址
	scheme := c.GetHeader("X-Forwarded-Proto")
	if scheme == "" {
		if c.Request.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := c.Request.Host

	c.Header("Content-Type", "text/html; charset=utf-8")

	var html strings.Builder
	html.WriteString(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Containerd 代理配置指南</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e4e4e4;
            min-height: 100vh;
            padding: 40px 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        h1 {
            text-align: center;
            margin-bottom: 10px;
            font-size: 2rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .subtitle {
            text-align: center;
            color: #888;
            margin-bottom: 40px;
        }
        .card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .card h2 {
            color: #667eea;
            margin-bottom: 16px;
            font-size: 1.25rem;
        }
        .info-row {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }
        .info-label {
            color: #888;
            min-width: 100px;
            font-size: 0.9rem;
        }
        .info-value {
            font-family: "Monaco", "Menlo", "Ubuntu Mono", monospace;
            background: rgba(0, 0, 0, 0.3);
            padding: 6px 12px;
            border-radius: 6px;
            color: #4ade80;
            word-break: break-all;
        }
        pre {
            background: rgba(0, 0, 0, 0.4);
            border-radius: 8px;
            padding: 20px;
            overflow-x: auto;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        code {
            font-family: "Monaco", "Menlo", "Ubuntu Mono", monospace;
            font-size: 0.9rem;
            line-height: 1.6;
            color: #e4e4e4;
        }
        .comment { color: #6a9955; }
        .string { color: #ce9178; }
        .keyword { color: #569cd6; }
        .number { color: #b5cea8; }
        .registry-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 12px;
            margin-top: 16px;
        }
        .registry-item {
            background: rgba(255, 255, 255, 0.03);
            padding: 12px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .registry-name {
            font-weight: 600;
            color: #667eea;
            margin-bottom: 4px;
        }
        .registry-endpoint {
            font-size: 0.85rem;
            color: #888;
            font-family: monospace;
        }
        .note {
            background: rgba(102, 126, 234, 0.1);
            border-left: 4px solid #667eea;
            padding: 16px;
            border-radius: 0 8px 8px 0;
            margin-top: 16px;
        }
        .note-title {
            color: #667eea;
            font-weight: 600;
            margin-bottom: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Containerd 代理配置指南</h1>
        <p class="subtitle">CRProxy - 容器镜像仓库代理服务</p>
`)

	// 服务信息卡片
	html.WriteString(`        <div class="card">
            <h2>服务信息</h2>
            <div class="info-row">
                <span class="info-label">服务地址:</span>
                <span class="info-value">` + scheme + `://` + host + `</span>
            </div>
`)
	if domainSuffix != "" {
		html.WriteString(`            <div class="info-row">
                <span class="info-label">域名后缀:</span>
                <span class="info-value">` + domainSuffix + `</span>
            </div>
`)
	} else {
		html.WriteString(`            <div class="info-row">
                <span class="info-label">模式:</span>
                <span class="info-value">单上游代理 (Solo Upstream)</span>
            </div>
`)
	}
	html.WriteString(`        </div>
`)

	// 配置说明卡片
	html.WriteString(`        <div class="card">
            <h2>配置说明</h2>
`)

	if domainSuffix == "" {
		// Solo upstream 模式 - 简化配置
		html.WriteString(`            <p style="margin-bottom: 16px; line-height: 1.6;">
                当前为 <strong>单上游代理模式</strong>，所有请求都会被转发到默认的镜像仓库。
                配置时直接将 <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">cri</code> 插件的
                <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">sandbox_image</code> 和镜像仓库地址指向此服务即可。
            </p>
            <pre><code><span class="comment"># /etc/containerd/config.toml</span>
<span class="keyword">version</span> = <span class="number">2</span>

<span class="keyword">[plugins."io.containerd.grpc.v1.cri".registry.mirrors]</span>
  <span class="keyword">[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]</span>
    <span class="keyword">endpoint</span> = [<span class="string">"` + scheme + `://` + host + `"</span>]

<span class="keyword">[plugins."io.containerd.grpc.v1.cri"]</span>
  <span class="keyword">sandbox_image</span> = <span class="string">"` + scheme + `://` + host + `/library/pause:3.9"</span></code></pre>
`)
	} else {
		// 多仓库模式 - 完整配置
		registryMap := GetRegistryMap()
		html.WriteString(`            <p style="margin-bottom: 16px; line-height: 1.6;">
                当前支持通过子域名访问不同的镜像仓库。配置时使用以下格式：
                <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">{registry}.` + domainSuffix + `</code>
            </p>
            <pre><code><span class="comment"># /etc/containerd/config.toml</span>
<span class="keyword">version</span> = <span class="number">2</span>

<span class="keyword">[plugins."io.containerd.grpc.v1.cri".registry.mirrors]</span>
`)
		for name := range registryMap {
			if name == "default" {
				continue
			}
			html.WriteString(`  <span class="keyword">[plugins."io.containerd.grpc.v1.cri".registry.mirrors."` + name + `.*"]</span>
    <span class="keyword">endpoint</span> = [<span class="string">"` + scheme + `://` + name + `.` + domainSuffix + `"</span>]
`)
		}
		html.WriteString(`  <span class="keyword">[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]</span>
    <span class="keyword">endpoint</span> = [<span class="string">"` + scheme + `://docker.` + domainSuffix + `"</span>]

<span class="keyword">[plugins."io.containerd.grpc.v1.cri"]</span>
  <span class="keyword">sandbox_image</span> = <span class="string">"` + scheme + `://docker.` + domainSuffix + `/library/pause:3.9"</span></code></pre>
`)

		// 可用仓库列表
		html.WriteString(`            <h3 style="margin-top: 24px; margin-bottom: 12px; color: #667eea;">可用仓库列表</h3>
            <div class="registry-grid">
`)
		for name, url := range registryMap {
			if name == "default" {
				continue
			}
			html.WriteString(`                <div class="registry-item">
                    <div class="registry-name">` + name + `</div>
                    <div class="registry-endpoint">` + url + `</div>
                </div>
`)
		}
		html.WriteString(`            </div>
`)
	}

	html.WriteString(`        </div>
`)

	// 重启命令卡片
	html.WriteString(`        <div class="card">
            <h2>应用配置</h2>
            <p style="margin-bottom: 16px; line-height: 1.6;">
                修改配置文件后，需要重启 containerd 服务使配置生效：
            </p>
            <pre><code><span class="comment"># 重启 containerd</span>
sudo systemctl restart containerd

<span class="comment"># 检查状态</span>
sudo systemctl status containerd</code></pre>
            <div class="note">
                <div class="note-title">提示</div>
                <p>如果使用了 TLS 证书，请确保证书已正确配置。对于自签名证书，需要在 containerd 中配置 insecure-registries 或将证书添加到系统信任库。</p>
            </div>
        </div>
    </div>
</body>
</html>`)

	c.String(http.StatusOK, html.String())
}
