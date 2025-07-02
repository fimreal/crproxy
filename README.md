# crproxy

A universal container image registry proxy that supports path-based routing.

## Features
- Path-based proxy for multiple registries (docker.io, gcr.io, quay.io, etc.)
- Automatic Bearer token authentication and caching
- Info/debug log output, supports log level switch
- Supports both binary and Docker deployment
- Simple configuration via command line or environment variables

## Quick Start

### (Optional) Terminal Proxy Configuration
```sh
export http_proxy="http://domain_or_ip:port"
export https_proxy=$http_proxy
```

### Build and Run (Local)
```sh
git clone https://github.com/fimreal/crproxy.git
cd crproxy
go run main.go
```

### Run with Docker
```sh
docker build -t crproxy .
docker run -it --rm -p 8080:8080 crproxy -port=8080
```

## Usage

Configure your Docker/Podman/Containerd to use this proxy as the registry endpoint, e.g.:
```
docker pull 127.0.0.1:8080/docker.io/library/alpine
```
Or for GCR:
```
docker pull 127.0.0.1:8080/gcr.io/google-containers/pause:3.9
```

## Command Line Arguments
| Argument   | Env         | Default | Description                |
|------------|-------------|---------|----------------------------|
| -port      | PORT        | 5000    | Listen port                |
| -debug     |             | false   | Enable debug log           |

## Log Levels
- Info: Proxy image and blob requests, startup info
- Debug: Upstream requests, token cache, authentication flow
- Error: Proxy errors, token errors

## Multi-arch Build
See `Makefile` for multi-platform cross compilation.

## License
MIT License. See [LICENSE](LICENSE).
