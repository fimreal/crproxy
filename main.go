package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TransportFactory 缓存每个上游 host 对应的 *http.Transport（保证 SNI 与连接复用）。
type TransportFactory struct {
	mu    sync.Mutex
	cache map[string]*http.Transport
}

func NewTransportFactory() *TransportFactory {
	return &TransportFactory{cache: make(map[string]*http.Transport)}
}

func (f *TransportFactory) Get(upHost string) *http.Transport {
	f.mu.Lock()
	defer f.mu.Unlock()
	if tr, ok := f.cache[upHost]; ok {
		return tr
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			ServerName: upHost,
		},
	}
	f.cache[upHost] = tr
	return tr
}

func deriveUpstream(reqHost, domainSuffix, defaultUpstream string) (string, error) {
	if reqHost == "" {
		return "", fmt.Errorf("empty reqHost")
	}
	// 处理可能包含端口的主机名
	hostOnly := reqHost
	if i := strings.LastIndex(reqHost, ":"); i != -1 {
		hostOnly = reqHost[:i]
	}

	// 检查是否为 IP 地址
	if net.ParseIP(hostOnly) != nil {
		return defaultUpstream, nil
	}
	if domainSuffix != "" && strings.HasSuffix(reqHost, domainSuffix) {
		upHost := strings.TrimSuffix(reqHost, domainSuffix)
		upHost = strings.TrimRight(upHost, ".")
		if !strings.Contains(upHost, ".") {
			return "", fmt.Errorf("invalid upstream request, %s", reqHost)
		}
		return upHost, nil
	}
	return defaultUpstream, nil
}

type ProxyHandler struct {
	domainSuffix    string
	defaultUpstream string
	trFactory       *TransportFactory
}

func NewProxyHandler(domainSuffix, defaultUpstream string) *ProxyHandler {
	return &ProxyHandler{
		domainSuffix:    strings.Trim(domainSuffix, "."),
		defaultUpstream: defaultUpstream,
		trFactory:       NewTransportFactory(),
	}
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upstream, err := deriveUpstream(r.Host, h.domainSuffix, h.defaultUpstream)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("Request: %s %s, Host: %s, Upstream: %s", r.Method, r.URL.Path, r.Host, upstream)
	target := &url.URL{Scheme: "https", Host: upstream}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host

			// 将 Host header 设置为上游纯域名（假定没有端口）
			req.Host = upstream

			// 可按需移除 Accept-Encoding
			req.Header.Del("Accept-Encoding")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[error] %s %s -> %s : %v", r.Method, r.URL.String(), upstream, err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
		FlushInterval: 100 * time.Millisecond,
	}

	// 给该上游复用 Transport，保证 SNI 与连接复用
	tr := h.trFactory.Get(upstream)
	rp.Transport = tr

	rp.ServeHTTP(w, r)
}

func main() {
	var listen string
	var domainSuffix string
	var defaultUpstream string

	flag.StringVar(&listen, "listen", ":5000", "backend listen address (Caddy should proxy to this)")
	flag.StringVar(&domainSuffix, "domain-suffix", "", "domain suffix for mirror hosts, e.g. mydomain.com; if empty use request host as upstream")
	flag.StringVar(&defaultUpstream, "default-upstream", "registry-1.docker.io", "default registry upstream")
	flag.Parse()

	handler := NewProxyHandler(domainSuffix, defaultUpstream)
	srv := &http.Server{
		Addr:    listen,
		Handler: handler,
	}
	log.Printf("backend proxy listening %s domain-suffix=%q default-upstream=%q", listen, domainSuffix, defaultUpstream)
	log.Fatal(srv.ListenAndServe())
}
