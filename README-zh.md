# crproxy

一个支持路径路由的通用容器镜像仓库代理。

## 特性
- 基于路径的多仓库代理（支持 docker.io、gcr.io、quay.io 等）
- 支持二进制和 Docker 部署
- 配置简单，支持命令行和环境变量

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

## 使用方法

将你的容器镜像前面加上代理地址，例如：
```
docker pull 127.0.0.1:8080/docker.io/library/alpine
```
或代理 GCR：
```
docker pull 127.0.0.1:8080/gcr.io/google-containers/pause:3.9
```

## 启动参数
| 参数      | 环境变量     | 默认值  | 说明                |
|-----------|--------------|---------|---------------------|
| -port     | PORT         | 5000    | 监听端口            |
| -debug    |              | false   | 开启 debug 日志     |

## 日志说明
- Info：镜像和 blob 代理请求、启动信息
- Debug：上游请求、token 缓存、认证流程
- Error：代理错误、token 错误

## 多架构构建
见 `Makefile`，支持多平台交叉编译。

## License
MIT 许可证，详见 [LICENSE](LICENSE)。 