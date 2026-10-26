package scan

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sentinel/internal/model"
)

type Target struct {
	Input  string
	Host   string
	Addr   net.IP
	Others []net.IP
	Port   int // explicit port given in the input, 0 if none
	IsIP   bool
}

type Options struct {
	Full    bool // scan all 65535 TCP ports instead of the common set
	Passive bool // query third-party sources (crt.sh) about the domain
	Local   bool // also audit the local Docker host
}

type EventKind int

const (
	EvStatus EventKind = iota
	EvFinding
	EvDone
)

type Event struct {
	Check   string
	Kind    EventKind
	Msg     string
	Finding model.Finding
}

type PortInfo struct {
	Port    int
	TLS     bool
	HTTP    bool
	Banner  string
	Service string
	Product string
	Version string
}

type Scan struct {
	T Target
	O Options

	mu    sync.Mutex
	ports map[int]*PortInfo
}

// ParseTarget accepts a URL, hostname, IPv4/IPv6 address, optionally with a port.
func ParseTarget(in string) (Target, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return Target{}, fmt.Errorf("destino vacío")
	}
	raw := in
	if !strings.Contains(raw, "://") {
		raw = "tcp://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return Target{}, fmt.Errorf("destino no válido: %q", in)
	}
	t := Target{Input: in, Host: u.Hostname()}
	if p := u.Port(); p != "" {
		t.Port, _ = strconv.Atoi(p)
	}

	var ips []net.IP
	if ip := net.ParseIP(t.Host); ip != nil {
		t.IsIP = true
		ips = []net.IP{ip}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, t.Host)
		if err != nil {
			return Target{}, fmt.Errorf("no se puede resolver %s: %w", t.Host, err)
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return Target{}, fmt.Errorf("%s no tiene direcciones IP", t.Host)
	}
	sort.SliceStable(ips, func(i, j int) bool { return ips[i].To4() != nil && ips[j].To4() == nil })
	t.Addr, t.Others = ips[0], ips[1:]
	return t, nil
}

func (s *Scan) addr(port int) string { return net.JoinHostPort(s.T.Addr.String(), strconv.Itoa(port)) }

func (s *Scan) sni() string {
	if s.T.IsIP {
		return ""
	}
	return s.T.Host
}

func (s *Scan) setPort(pi *PortInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ports == nil {
		s.ports = map[int]*PortInfo{}
	}
	s.ports[pi.Port] = pi
}

func (s *Scan) portList(filter func(*PortInfo) bool) []PortInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []PortInfo
	for _, p := range s.ports {
		if filter == nil || filter(p) {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func (s *Scan) Ports() []PortInfo   { return s.portList(nil) }
func (s *Scan) TLSPorts() []PortInfo { return s.portList(func(p *PortInfo) bool { return p.TLS }) }
func (s *Scan) HTTPPorts() []PortInfo {
	return s.portList(func(p *PortInfo) bool { return p.HTTP })
}

func (s *Scan) updateVersion(port int, service, product, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.ports[port]; p != nil {
		if service != "" {
			p.Service = service
		}
		p.Product, p.Version = product, version
	}
}

type emitter struct {
	ctx   context.Context
	ch    chan<- Event
	check string
	seen  *sync.Map
}

func (e emitter) send(ev Event) {
	ev.Check = e.check
	select {
	case e.ch <- ev:
	case <-e.ctx.Done():
	}
}

func (e emitter) status(format string, a ...any) {
	e.send(Event{Kind: EvStatus, Msg: fmt.Sprintf(format, a...)})
}

func (e emitter) find(f model.Finding) {
	f.Check = e.check
	Enrich(&f)
	key := fmt.Sprintf("%s|%d|%s", f.Check, f.Port, f.Title)
	if _, dup := e.seen.LoadOrStore(key, true); dup {
		return
	}
	e.send(Event{Kind: EvFinding, Finding: f})
}
