package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinel/internal/model"
)

func commonPorts() []int {
	set := map[int]bool{}
	for p := 1; p <= 1024; p++ {
		set[p] = true
	}
	for p := range portKB {
		set[p] = true
	}
	for _, r := range [][2]int{{2375, 2380}, {3000, 3010}, {5000, 5010}, {5900, 5910}, {8000, 8100}, {8440, 8450}, {9000, 9010}, {9090, 9100}, {10000, 10010}, {21115, 21119}, {34400, 34400}} {
		for p := r[0]; p <= r[1]; p++ {
			set[p] = true
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func allPorts() []int {
	out := make([]int, 65535)
	for i := range out {
		out[i] = i + 1
	}
	return out
}

func checkPorts(ctx context.Context, s *Scan, e emitter) {
	ports := commonPorts()
	if s.O.Full {
		ports = allPorts()
	}
	if s.T.Port != 0 && !contains(ports, s.T.Port) {
		ports = append(ports, s.T.Port)
	}
	if len(s.T.Others) > 0 {
		e.find(model.Finding{
			Title: "El nombre resuelve a varias IP; solo se audita la primera", Severity: model.Info,
			Evidence:    fmt.Sprintf("auditada: %s, otras: %v", s.T.Addr, s.T.Others),
			Remediation: "Repite la auditoría contra cada IP (o IPv4 e IPv6 por separado) para cubrir toda la superficie.",
		})
	}
	e.status("escaneando %d puertos TCP en %s…", len(ports), s.T.Addr)

	var (
		mu      sync.Mutex
		open    []int
		scanned atomic.Int64
		wg      sync.WaitGroup
		jobs    = make(chan int, 1024)
	)
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: 1200 * time.Millisecond}
			for p := range jobs {
				c, err := d.DialContext(ctx, "tcp", s.addr(p))
				if err == nil {
					c.Close()
					mu.Lock()
					open = append(open, p)
					mu.Unlock()
				}
				if n := scanned.Add(1); n%2000 == 0 {
					e.status("%d/%d puertos · %d abiertos", n, len(ports), len(open))
				}
			}
		}()
	}
feed:
	for _, p := range ports {
		select {
		case jobs <- p:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	sort.Ints(open)

	if len(open) == 0 {
		e.status("ningún puerto abierto detectado")
		return
	}
	e.status("%d puertos abiertos; identificando servicios…", len(open))
	sem := make(chan struct{}, 16)
	for _, p := range open {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			pi := probePort(ctx, s, p)
			s.setPort(pi)
			e.find(portFinding(*pi))
			if pi.Service == "redis" {
				e.find(model.Finding{
					Title: fmt.Sprintf("Redis sin autenticación en %d/tcp", p), Severity: model.Critical, Port: p,
					Detail:      "Responde a PING sin credenciales: cualquiera puede leer/escribir datos y, vía CONFIG SET, escribir ficheros (RCE).",
					Evidence:    pi.Banner,
					Remediation: "Cierra el puerto a internet, bind a 127.0.0.1, define `requirepass`/ACL y `protected-mode yes`.",
				})
			}
		}(p)
	}
	wg.Wait()
	e.status("%d puertos abiertos", len(open))
}

func contains(xs []int, v int) bool {
	i := sort.SearchInts(xs, v)
	return i < len(xs) && xs[i] == v
}

func cleanBanner(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 32 && c < 127 {
			sb.WriteByte(c)
		} else if c == '\n' || c == '\r' {
			sb.WriteByte(' ')
		} else {
			sb.WriteByte('.')
		}
	}
	out := strings.TrimSpace(sb.String())
	if len(out) > 160 {
		out = out[:160] + "…"
	}
	return out
}

func classify(pi *PortInfo) {
	b := pi.Banner
	switch {
	case strings.HasPrefix(b, "SSH-"):
		pi.Service = "ssh"
	case strings.HasPrefix(b, "HTTP/"):
		pi.Service, pi.HTTP = "http", true
	case strings.HasPrefix(b, "RFB "):
		pi.Service = "vnc"
	case strings.HasPrefix(b, "220") && strings.Contains(strings.ToLower(b), "ftp"):
		pi.Service = "ftp"
	case strings.HasPrefix(b, "220") && strings.Contains(strings.ToLower(b), "smtp"):
		pi.Service = "smtp"
	case strings.HasPrefix(b, "+OK"):
		pi.Service = "pop3"
	case strings.HasPrefix(b, "* OK"):
		pi.Service = "imap"
	case strings.Contains(strings.ToLower(b), "mysql") || strings.Contains(b, "mariadb"):
		pi.Service = "mysql"
	}
}

// probePort identifies what speaks on an open port: banner-first protocols,
// TLS (with or without HTTP inside) or plain HTTP.
func probePort(ctx context.Context, s *Scan, port int) *PortInfo {
	pi := &PortInfo{Port: port}
	to := 2 * time.Second
	dial := func() net.Conn {
		d := net.Dialer{Timeout: to}
		c, err := d.DialContext(ctx, "tcp", s.addr(port))
		if err != nil {
			return nil
		}
		return c
	}
	buf := make([]byte, 1024)

	if port == 6379 {
		if c := dial(); c != nil {
			c.SetDeadline(time.Now().Add(to))
			c.Write([]byte("PING\r\n"))
			n, _ := c.Read(buf)
			c.Close()
			if strings.HasPrefix(string(buf[:n]), "+PONG") {
				pi.Service, pi.Banner = "redis", "+PONG (sin autenticación)"
				return pi
			}
		}
	}

	// 1. servers that speak first (ssh, ftp, smtp…)
	if c := dial(); c != nil {
		c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
		n, _ := c.Read(buf)
		c.Close()
		if n > 0 {
			pi.Banner = cleanBanner(buf[:n])
			classify(pi)
			return pi
		}
	}

	// 2. TLS, possibly carrying HTTP
	if c := dial(); c != nil {
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: s.sni()})
		tc.SetDeadline(time.Now().Add(to))
		if tc.Handshake() == nil {
			pi.TLS = true
			fmt.Fprintf(tc, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: sentinel\r\n\r\n", s.T.Host)
			n, _ := tc.Read(buf)
			tc.Close()
			pi.Banner = cleanBanner(firstLine(buf[:n]))
			if strings.HasPrefix(pi.Banner, "HTTP/") {
				pi.Service, pi.HTTP = "https", true
			} else {
				pi.Service = "tls"
			}
			return pi
		}
		c.Close()
	}

	// 3. plain HTTP
	if c := dial(); c != nil {
		c.SetDeadline(time.Now().Add(to))
		fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: sentinel\r\n\r\n", s.T.Host)
		n, _ := c.Read(buf)
		c.Close()
		if n > 0 {
			pi.Banner = cleanBanner(firstLine(buf[:n]))
			classify(pi)
		}
	}
	return pi
}

func firstLine(b []byte) []byte {
	if i := strings.IndexAny(string(b), "\r\n"); i >= 0 {
		return b[:i]
	}
	return b
}
