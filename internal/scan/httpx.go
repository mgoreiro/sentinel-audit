package scan

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

type resp struct {
	Status int
	Header http.Header
	Body   string
	Err    error
}

// get issues a request to the already-resolved IP while keeping the original
// hostname for the Host header and SNI. Redirects are not followed.
func (s *Scan) get(ctx context.Context, pi PortInfo, method, path string, hdr map[string]string) resp {
	scheme := "http"
	if pi.TLS {
		scheme = "https"
	}
	u := scheme + "://" + net.JoinHostPort(s.T.Host, strconv.Itoa(pi.Port)) + path
	d := &net.Dialer{Timeout: 4 * time.Second}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, s.addr(pi.Port))
		},
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{
		Transport:     tr,
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return resp{Err: err}
	}
	req.Header.Set("User-Agent", "sentinel-audit/1.0")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := cl.Do(req)
	if err != nil {
		return resp{Err: err}
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 128<<10))
	return resp{Status: r.StatusCode, Header: r.Header, Body: string(b)}
}
