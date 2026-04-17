# crproxy

A universal container image registry proxy that supports domain-based routing.

## Features
- Domain-based proxy for multiple registries (docker.io, gcr.io, quay.io, etc.)
- Automatic Bearer token authentication and proxying
- Automatic redirect following (handles 307 redirects internally)
- Local cache support for image blobs with streaming I/O (low memory usage)
- Structured JSON logging with request tracing and configurable log levels
- Web-based admin interface with token authentication (full version only)
- Self-update capability from GitHub releases (full version only)
- Supports both binary and Docker deployment
- Simple configuration via command line arguments
- Health check endpoint (`/healthz`)
- Registry information endpoint (`/help`)
- Supports both SHA256 and SHA512 digest algorithms

## Versions

crproxy provides two versions to meet different deployment needs:

### Full Version (Default)

Complete functionality with all features enabled:
- Web-based admin interface with authentication
- Runtime configuration via config file
- Statistics collection and monitoring
- Self-update capability
- Containerd configuration help page

**Build:**
```sh
make build
# or
go build -o crproxy .
```

### Lite Version

Minimal version with only core proxy and cache functionality:
- Core registry proxy with domain-based routing
- Local blob caching with streaming I/O
- Structured JSON logging
- Health check endpoint
- ~50% smaller binary size (~12MB vs ~23MB)

**Removed features:**
- Web admin interface and authentication
- Statistics collection
- Config file support (command-line args only)
- Self-update capability
- Containerd help page

**Use cases:**
- Resource-constrained environments (edge, IoT, small VPS)
- Simple proxy-only deployments
- CI/CD pipelines where minimal footprint matters

**Build:**
```sh
make build-lite
# or
go build -tags lite -o crproxy-lite .
```

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

**Full version:**
```sh
docker build -t crproxy .
docker run -it --rm -p 8080:8080 crproxy -listen=:8080
```

**Lite version:**
```sh
docker build -f Dockerfile.lite -t crproxy:lite .
docker run -it --rm -p 8080:8080 crproxy:lite -listen=:8080
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

### Self-Update (Full Version Only)

Update to the latest version from GitHub releases:

```sh
# Check and update to the latest stable version
crproxy -update

# The old binary will be backed up as crproxy.backup
# Restart the service to use the new version
```

Features:
- Downloads the correct binary for your OS and architecture
- Automatically backs up the old version
- Only updates to stable releases (no pre-releases)
- Verifies if already at the latest version

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

### Common Arguments (Both Versions)

| Argument | Default | Description |
|----------|----------|-------------|
| `-listen` | `:5000` | Backend listen address and port |
| `-domain-suffix` | (empty) | Domain suffix for mirror hosts, e.g. `mydomain.com`. If empty, uses default registry as upstream |
| `-registry-map` | (embedded) | Registry map file path. Defaults to embedded `registrymap.json`. **Note:** Lite version only supports local file path, not URL |
| `-default-registry` | (empty) | Default registry URL to use when no domain suffix is configured or when accessing via IP address |
| `-cache-dir` | (empty) | Local cache directory for caching image blobs. Disabled if empty. Only caches blobs, not manifests |
| `-log-level` | `info` | Log level: debug, info, warn, error |
| `-help` | - | Show help information |
| `-version` | - | Show version and build time |

### Full Version Only Arguments

| Argument | Default | Description |
|----------|----------|-------------|
| `-config-file` | `./crproxy-config.json` | Configuration file path for runtime configuration |
| `-stats-dir` | (empty) | Directory for persisting statistics to JSON file. Statistics are saved every 5 minutes and on shutdown |
| `-update` | - | Update to latest version from GitHub releases |

**Note:** Lite version only supports command-line arguments. Configuration file and self-update features are not available in the lite version.

### Environment Variables

| Variable | Description | Version |
|----------|-------------|---------|
| `DEBUG` | Set to `1` to enable debug logging (backward compatibility). Equivalent to `-log-level=debug` | Both |
| `http_proxy` / `https_proxy` | Optional proxy settings for outbound connections | Both |
| `ADMIN_PASSWORD` | Admin interface password. If not set, admin interface is disabled | Full only |

## Admin Interface (Full Version Only)

crproxy provides a web-based admin interface for viewing and editing configuration.

### Features

- **Configuration Management**: View and edit registry mappings and service settings
- **Statistics Dashboard**: Real-time monitoring with:
  - Service status (uptime, request count, traffic)
  - Cache statistics (hit rate, hits/misses, storage usage)
  - Client statistics (by type: Docker, Podman, containerd, etc.)
  - Upstream statistics (requests per registry)
  - Image statistics (most pulled images)
  - Client IP statistics (top requesting IPs)
- **System Update**: Check and apply updates from GitHub releases
- **Dark/Light Mode**: Theme toggle with auto system preference detection
- **i18n**: English and Chinese language support

### Enable Admin Interface

Set the admin password via environment variable:

```bash
# Generate a strong password
openssl rand -base64 32

# Set the password
export ADMIN_PASSWORD=your_secure_password_here
crproxy -listen=:5000
```

Or set it in the config file (`crproxy-config.json`):

```json
{
  "adminPassword": "your_secure_password_here"
}
```

### Access Admin Interface

Once configured, access the admin interface at:

```
http://your-server:5000/admin
```

### Docker Example

**Full version (with admin interface):**
```bash
docker run -it --rm -p 5000:5000 \
  -e ADMIN_PASSWORD=your_secure_password \
  crproxy:latest
```

**Lite version (no admin interface):**
```bash
docker run -it --rm -p 5000:5000 \
  crproxy:lite -listen=:5000 -cache-dir=/cache
```

**Note**: If `ADMIN_PASSWORD` is not set, the admin interface will be disabled and return a 403 error.

## API Endpoints

- `GET /healthz` - Health check endpoint, returns `{"status": "ok"}` (both versions)
- `GET /help` - Returns the registry map configuration as JSON (full version only)
- `GET /v2/*` - Proxy requests to container registries (both versions)
- `GET /token/*` - Proxy authentication token requests (both versions)
- `GET /admin` - Admin interface (requires password authentication, full version only)
- `GET /containerd` - Containerd configuration help page (full version only)

## Statistics Persistence (Full Version Only)

When `-stats-dir` is specified, crproxy will persist statistics to a JSON file, allowing statistics to survive service restarts.

```bash
# Enable statistics persistence
crproxy -stats-dir=/var/lib/crproxy/stats

# Or with Docker
docker run -it --rm -p 5000:5000 \
  -v /path/to/stats:/stats \
  crproxy:latest -stats-dir=/stats
```

**Features:**
- Statistics loaded from file on startup
- Auto-saved every 5 minutes
- Saved on graceful shutdown (SIGINT/SIGTERM)
- Captures: request counts, cache stats, client types, upstreams, images, client IPs, traffic

**Generated file (`stats.json`):**
```json
{
  "totalRequests": 1234,
  "cacheHits": 456,
  "cacheMisses": 78,
  "clients": {"docker": 800, "podman": 300, "containerd": 134},
  "upstreams": {"registry-1.docker.io": 900, "quay.io": 334},
  "images": {"library/alpine": 200, "library/nginx": 150},
  "clientIPs": {"192.168.1.100": 500, "10.0.0.1": 300},
  "bytesSent": 1073741824,
  "savedAt": "2024-01-15T10:30:45Z"
}
```

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
