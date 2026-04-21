package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
)

type ReverseProxy struct{}

func New() *ReverseProxy {
	return &ReverseProxy{}
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request, upstream string) error {
	target, err := url.Parse(upstream)
	if err != nil {
		return fmt.Errorf("parse upstream url: %w", err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(target)
			req.Out.URL.Path = singleJoiningSlash(target.Path, r.URL.Path)
			req.Out.URL.RawQuery = r.URL.RawQuery
			req.Out.Host = target.Host
			// These headers are internal to the limiter and should not leak to the
			// customer's upstream service.
			req.Out.Header.Del("Authorization")
			req.Out.Header.Del("X-API-ID")
		},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, proxyErr error) {
			http.Error(rw, "upstream proxy error: "+proxyErr.Error(), http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
	return nil
}

func singleJoiningSlash(a, b string) string {
	switch {
	case strings.HasSuffix(a, "/") && strings.HasPrefix(b, "/"):
		return a + b[1:]
	case !strings.HasSuffix(a, "/") && !strings.HasPrefix(b, "/"):
		return a + "/" + path.Clean(b)
	default:
		return a + b
	}
}
