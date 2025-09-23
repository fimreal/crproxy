# crproxy

A universal container image registry proxy that supports domain-based routing.

## Features
- Domain-based proxy for multiple registries (docker.io, gcr.io, quay.io, etc.)
- Automatic Bearer token authentication and caching
- Info/debug log output, supports log level switch
- Supports both binary and Docker deployment
- Simple configuration via command line or environment variables

## Quick Start

### (Optional) Terminal Proxy Configuration
```sh
export http_proxy="http://domain_or_ip:port";
export https_proxy=$http_proxy;
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

## Configure Image Registries

Configure image registry mappings through registrymap.json, supporting local files or URLs configured at startup.

## Usage

Container images will be matched based on the request domain and forwarded to the corresponding image registry.

When the current request is to an IP or a domain configured with -domain-suffix, it will match to the default image registry (specified by the registry configured with -registry-map, or a random image registry if not specified).

Add the proxy address to the front of your container image to use the default image registry proxy, for example:

```bash
docker pull 127.0.0.1:8080/docker.io/library/alpine
```

Specify the image registry through domain name. For example, when -domain-suffix is configured as mydomain.com:

```bash
# Request will proxy gcr.io/google-containers/pause:3.9
docker pull gcr.mydomain.com/google-containers/pause:3.9
```

## Command Line Arguments
```bash
# crproxy -help
Usage of /crproxy:               
  -domain-suffix string
        domain suffix for mirror hosts, e.g. mydomain.com; if empty use default registry as upstream
  -help
        show help
  -listen string
        backend listen address (default ":5000")
  -registry-map string
        registry map file path or URL (default: embed registrymap.json)
  -version
        show version
```

## Multi-arch Build
See [Makefile](Makefile) for multi-platform cross compilation.

## License
MIT License. See [LICENSE](LICENSE).
