# crproxy

一个支持基于域名路由的通用容器镜像仓库代理。

## 特性
- 基于域名的多仓库代理（支持 docker.io、gcr.io、quay.io 等）
- 自动 Bearer token 认证和代理
- 自动重定向跟随（内部处理 307 重定向）
- 本地缓存支持（仅缓存镜像层 blobs，不缓存清单 manifests）
- 信息/调试日志输出，通过 `DEBUG` 环境变量控制日志级别
- 支持二进制和 Docker 部署
- 通过命令行参数简单配置
- 健康检查端点 (`/healthz`)
- 仓库信息端点 (`/help`)

## 快速开始

### （可选）终端代理配置
```sh
export http_proxy="http://domain_or_ip:port";
export https_proxy=$http_proxy;
```

### 本地构建与运行
```sh
git clone https://github.com/fimreal/crproxy.git
cd crproxy
go run main.go
```

### Docker 运行
```sh
docker build -t crproxy .
docker run -it --rm -p 8080:8080 crproxy -listen=:8080
```

### 启用缓存运行
```sh
# 启用本地缓存（缓存镜像层）
crproxy -cache-dir=/tmp/crproxy-cache

# 或使用 Docker
docker run -it --rm -p 8080:8080 \
  -v /path/to/cache:/cache \
  crproxy -listen=:8080 -cache-dir=/cache
```

### 启用调试日志
```sh
# 设置 DEBUG 环境变量以启用详细日志
DEBUG=1 crproxy -listen=:8080
```

## 配置镜像仓库

通过 [registrymap.json](registrymap.json) 配置镜像仓库映射关系，支持本地文件或者 URL 在启动时配置。

示例 `registrymap.json`：
```json
{
    "default": "https://registry-1.docker.io",
    "docker": "https://registry-1.docker.io",
    "ecr": "https://public.ecr.aws",
    "gcr": "https://gcr.io",
    "ghcr": "https://ghcr.io",
    "k8s": "https://registry.k8s.io",
    "k8sgcr": "https://k8s.gcr.io",
    "quay": "https://quay.io"
}
```

`default` 键指定了默认仓库，当未配置域名后缀或通过 IP 地址访问时使用。

你也可以通过 `-default-registry` 命令行参数覆盖默认仓库：

```bash
# 通过命令行覆盖默认仓库
crproxy -default-registry=https://registry-1.docker.io
```

**注意**：`-default-registry` 参数的优先级高于 `registrymap.json` 中的 `default` 键。

## 使用方法

容器镜像会根据请求域名匹配，并转发请求到对应的镜像仓库。

### 使用默认仓库（IP 或域名后缀）

当通过 IP 地址或配置了 `-domain-suffix` 的域名访问时，将使用默认仓库：

```bash
# 使用 IP 地址
docker pull 127.0.0.1:5000/library/alpine

# 使用域名后缀（当 -domain-suffix=mydomain.com 时）
docker pull mydomain.com/library/alpine
```

### 使用基于域名的路由

当配置了 `-domain-suffix` 时，可以通过子域名指定仓库：

```bash
# 配置 -domain-suffix=mydomain.com

# 请求会代理到 gcr.io
docker pull gcr.mydomain.com/google-containers/pause:3.9

# 请求会代理到 quay.io
docker pull quay.mydomain.com/prometheus/prometheus:latest

# 请求会代理到 docker.io（默认）
docker pull docker.mydomain.com/library/nginx:latest
```

### 容器运行时配置

**containerd**: 修改 mirror 配置，参考 [containerd CRI 配置](https://github.com/containerd/containerd/blob/main/docs/cri/config.md)

**podman**: 修改 registry 配置，参考 [Podman registry 配置](https://www.redhat.com/en/blog/manage-container-registries)

## 启动参数

| 参数             | 默认值              | 说明                                       |
|------------------|---------------------|--------------------------------------------|
| `-listen`        | `:5000`             | 监听地址和端口                             |
| `-domain-suffix` | (空)                | 域名后缀，用于镜像主机，例如 `mydomain.com`。如果为空，使用默认仓库作为上游 |
| `-registry-map`  | (嵌入)              | registry 映射文件路径或 URL。默认为嵌入的 `registrymap.json` |
| `-default-registry` | (空)            | 默认仓库 URL，当未配置域名后缀或通过 IP 地址访问时使用。会覆盖 registry map 中的 `default` 键 |
| `-cache-dir`     | (空)                | 本地缓存目录，用于缓存镜像层。如果为空则禁用缓存。仅缓存 blobs，不缓存 manifests |
| `-help`          | -                   | 显示帮助信息                               |
| `-version`       | -                   | 显示版本和构建时间                         |

### 环境变量

| 变量 | 说明 |
|------|------|
| `DEBUG` | 设置为 `1` 以启用调试日志。显示详细的请求/响应信息、重定向和缓存操作 |
| `http_proxy` / `https_proxy` | 可选，用于出站连接的代理设置 |

## API 端点

- `GET /healthz` - 健康检查端点，返回 `{"status": "ok"}`
- `GET /help` - 返回 registry 映射配置（JSON 格式）
- `GET /v2/*` - 代理容器仓库请求
- `GET /token/*` - 代理认证 token 请求

## 缓存功能

当指定 `-cache-dir` 时，crproxy 会在本地缓存镜像层（blobs）。这可以显著加快后续拉取相同镜像的速度。

**重要说明：**
- 仅缓存 blobs（镜像层），不缓存 manifests（清单文件），确保始终获取最新的清单
- 缓存基于内容寻址存储，使用 SHA256 摘要
- 在提供缓存内容之前会验证完整性
- 缓存异步写入，避免阻塞响应

## 重定向处理

crproxy 会自动在内部处理 HTTP 重定向（301, 302, 307, 308）。当仓库返回重定向到不同域名时（例如 Docker Hub 重定向到 Cloudflare CDN），crproxy 会在服务端跟随重定向，因此客户端无需直接请求重定向的 URL。

## 多架构构建

见 [Makefile](Makefile)，支持多平台交叉编译。

## License
MIT 许可证，详见 [LICENSE](LICENSE)。 