package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/gin-gonic/gin"
)

var DomainSuffix string
var DefaultUpstream string

// forward handles proxy requests
func forward(c *gin.Context) {
	tokenServer := "auth.docker.io"
	DefaultUpstream := "dockerhub.2fw.top"

	for k, vals := range c.Request.Header {
		log.Printf("%s: %s ", k, strings.Join(vals, ","))
	}

	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = DefaultUpstream
			req.Host = DefaultUpstream

			log.Printf("proxy: %s %s %s", c.Request.Method, c.Request.Host, c.Request.URL.String())
		},
		ModifyResponse: func(resp *http.Response) error {
			realm := resp.Header.Get("Www-Authenticate")
			if realm != "" && strings.Contains(realm, "https://"+tokenServer+"/token") {
				newRealm := strings.Replace(realm, "https://"+tokenServer+"/token", "http://192.168.10.55:5000/token", 1)
				resp.Header.Set("Www-Authenticate", newRealm)
			}

			for k, vals := range resp.Header {
				log.Printf("Req Header: %s: %s\n", k, strings.Join(vals, ","))
			}
			return nil
		},
	}
	proxy.ServeHTTP(c.Writer, c.Request)
}

func main() {
	var listen string

	flag.StringVar(&listen, "listen", ":5000", "backend listen address")
	// flag.StringVar(&DomainSuffix, "domain-suffix", "", "domain suffix for mirror hosts, e.g. mydomain.com; if empty use request host as upstream")
	flag.StringVar(&DefaultUpstream, "default-upstream", "registry-1.docker.io", "default registry upstream")
	flag.Parse()

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())

	r.Any("/v2/*path", forward)
	r.Any("/token", forward)

	log.Printf("crproxy listening on %s [domain-suffix=%q default-upstream=%q]", listen, DomainSuffix, DefaultUpstream)
	log.Fatal(r.Run(listen))
}
