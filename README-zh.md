# crproxy

一个支持基于域名路由的通用容器镜像仓库代理。

## 特性
- 基于域名的多仓库代理（支持 docker.io、gcr.io、quay.io 等）
- 支持二进制和 Docker 部署
- 极简功能，只做该做的事

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
docker run -it --rm -p 8080:8080 crproxy -port=8080
```

## 配置镜像仓库

通过 [registrymap.json](registrymap.json) 配置镜像仓库映射关系，支持本地文件或者 URL 在启动时配置。

## 使用方法

容器镜像会根据请求域名匹配，并转发请求到对应的镜像仓库。

例如当前请求的是 ip 或者 `-domain-suffix` 配置的域名时，则会匹配到默认镜像仓库(会由 `-registry-map` 配置的 registry 指定，如果没有则为随机镜像仓库)

将你的容器镜像前面加上代理地址，会使用默认镜像仓库代理，例如：
```
docker pull 127.0.0.1:5000/library/alpine
```

通过域名制定镜像仓库，例如 `-domain-suffix` 配置为 `mydomain.com`时：
```
# 请求会代理 gcr.io/google-containers/pause:3.9
docker pull gcr.mydomain.com/google-containers/pause:3.9
```

containerd 修改 mirror 配置参考：https://github.com/containerd/containerd/blob/main/docs/cri/config.md

podman 修改配置参考：https://www.redhat.com/en/blog/manage-container-registries

## 启动参数
| 参数             | 默认值              | 说明                                       |
|------------------|---------------------|--------------------------------------------|
| -listen          | :5000               | 监听地址和端口                             |
| -domain-suffix   |                     | 域名后缀，用于镜像主机，例如 mydomain.com |
| -registry-map    | embed registrymap.json | registry映射文件路径或URL                  |
| -help            |                     | 显示帮助信息                               |

## 多架构构建
见 [Makefile](Makefile)，支持多平台交叉编译。

## License
MIT 许可证，详见 [LICENSE](LICENSE)。 