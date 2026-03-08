# crproxy

A universal container image registry proxy that supports domain-based routing.

## Features
- Domain-based proxy for multiple registries (docker.io, gcr.io, quay.io, etc.)
- Automatic Bearer token authentication and proxying
- Automatic redirect following (handles 307 redirects internally)
- Local cache support for image blobs with streaming I/O (low memory usage)
- Structured JSON logging with request tracing and configurable log levels
- Supports both binary and Docker deployment
- Simple configuration via command line arguments
- Health check endpoint (`/healthz`)
- Registry information endpoint (`/help`)
- Supports both SHA256 and SHA512 digest algorithms

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
docker run -it --rm -p 8080:8080 crproxy -listen=:8080
```

### Run with Cache Enabled
```sh
# Enable local cache for image blobs
crproxy -cache-dir=/tmp/crproxy-cache

# Or with Docker
docker run -it --rm -p 8080:8080 \
  -v /path/to/cache:/cache \
  crproxy -listen=:8080 -cache-dir=/cache
```

### Configure Log Level

```sh
# Set log level via command line (debug, info, warn, error)
crproxy -listen=:8080 -log-level=debug

# Or use DEBUG environment variable for backward compatibility
DEBUG=1 crproxy -listen=:8080
```

## Configure Image Registries

Configure image registry mappings through `registrymap.json`, supporting local files or URLs configured at startup.

### Quick Start for Single Registry

If you only need to proxy a single registry, use `-default-registry` without creating a configuration file:

```bash
# Proxy registry.k8s.io only
crproxy -default-registry=https://registry.k8s.io -listen=:5000

# Pull images directly
docker pull 127.0.0.1:5000/pause:3.9
docker pull 127.0.0.1:5000/kube-apiserver:v1.28.0
```

### Multiple Registries Configuration

Example `registrymap.json` for multiple registries:
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

The `default` key specifies the default registry used when no domain suffix is configured or when accessing via IP address.

You can also override the default registry using the `-default-registry` command line argument:

```bash
# Override default registry via command line
crproxy -default-registry=https://registry-1.docker.io
```

**Note**: The `-default-registry` parameter takes precedence over the `default` key in `registrymap.json`.

## Usage

Container images will be matched based on the request domain and forwarded to the corresponding image registry.

### Using Default Registry (IP or Domain Suffix)

When accessing via IP address or the domain configured with `-domain-suffix`, requests will use the default registry:

```bash
# Using IP address
docker pull 127.0.0.1:5000/library/alpine

# Using domain suffix (when -domain-suffix=mydomain.com)
docker pull mydomain.com/library/alpine
```

### Using Domain-Based Routing

When `-domain-suffix` is configured, you can specify registries using subdomains:

```bash
# Configure with -domain-suffix=mydomain.com

# Request will proxy to gcr.io
docker pull gcr.mydomain.com/google-containers/pause:3.9

# Request will proxy to quay.io
docker pull quay.mydomain.com/prometheus/prometheus:latest

# Request will proxy to docker.io (default)
docker pull docker.mydomain.com/library/nginx:latest
```

### Container Runtime Configuration

**containerd**: Modify mirror configuration. See [containerd CRI config](https://github.com/containerd/containerd/blob/main/docs/cri/config.md)

**podman**: Modify registry configuration. See [Podman registry config](https://www.redhat.com/en/blog/manage-container-registries)

## Command Line Arguments

| Argument | Default | Description |
|----------|----------|-------------|
| `-listen` | `:5000` | Backend listen address and port |
| `-domain-suffix` | (empty) | Domain suffix for mirror hosts, e.g. `mydomain.com`. If empty, uses default registry as upstream |
| `-registry-map` | (embedded) | Registry map file path or URL. Defaults to embedded `registrymap.json` |
| `-default-registry` | (empty) | Default registry URL to use when no domain suffix is configured or when accessing via IP address. Overrides the `default` key in registry map |
| `-cache-dir` | (empty) | Local cache directory for caching image blobs. Disabled if empty. Only caches blobs, not manifests |
| `-log-level` | `info` | Log level: debug, info, warn, error |
| `-help` | - | Show help information |
| `-version` | - | Show version and build time |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `DEBUG` | Set to `1` to enable debug logging (backward compatibility). Equivalent to `-log-level=debug` |
| `http_proxy` / `https_proxy` | Optional proxy settings for outbound connections |

## API Endpoints

- `GET /healthz` - Health check endpoint, returns `{"status": "ok"}`
- `GET /help` - Returns the registry map configuration as JSON
- `GET /v2/*` - Proxy requests to container registries
- `GET /token/*` - Proxy authentication token requests

## Cache Feature

When `-cache-dir` is specified, crproxy will cache image blobs (layers) locally. This can significantly speed up subsequent pulls of the same images.

**Important Notes:**
- Only blobs are cached, not manifests (to ensure you always get the latest manifest)
- Cache is based on content-addressable storage using SHA256 or SHA512 digests
- Cached blobs are validated for integrity before serving
- Cache is written using streaming I/O to minimize memory usage
- Supports concurrent cache writes without blocking responses

## Redirect Handling

crproxy automatically handles HTTP redirects (301, 302, 307, 308) internally. When a registry returns a redirect to a different domain (e.g., Docker Hub redirecting to Cloudflare CDN), crproxy will follow the redirect server-side, so clients don't need to make direct requests to the redirected URL.

## Structured Logging

crproxy uses structured JSON logging with request tracing capabilities:

- Each request is assigned a unique request ID (via `X-Request-ID` header)
- All logs are output in JSON format for easy parsing and aggregation
- Configurable log levels: `debug`, `info`, `warn`, `error`
- Access logs include detailed request information: method, path, status, latency, client IP, cache status

Example log output:
```json
{"time":"2024-01-15T10:30:45.123Z","level":"INFO","msg":"request","request_id":"a1b2c3d4e5f6","method":"GET","path":"/v2/library/alpine/manifests/latest","status":200,"latency_ms":45,"size":1024,"client_ip":"192.168.1.100","cache":"HIT"}
```

## Multi-arch Build

See [Makefile](Makefile) for multi-platform cross compilation.

## License
MIT License. See [LICENSE](LICENSE).
