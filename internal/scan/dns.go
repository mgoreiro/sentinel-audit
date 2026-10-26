package scan

import (
	"context"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"sentinel/internal/model"
)

// openResolver sends a recursive query for a name we do not host; an answer
// means the server resolves for anyone on the internet.
func openResolver(ip net.IP) (bool, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0xBEEF, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return false, err
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("google.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return false, err
	}
	msg, err := b.Finish()
	if err != nil {
		return false, err
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), "53"), 3*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		return false, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	if err != nil {
		return false, err
	}
	if !h.Response || h.RCode != dnsmessage.RCodeSuccess || !h.RecursionAvailable {
		return false, nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false, err
	}
	ans, err := p.AllAnswers()
	return err == nil && len(ans) > 0, err
}

func checkDNS(ctx context.Context, s *Scan, e emitter) {
	e.status("probando si %s actúa como resolver DNS abierto (UDP 53)…", s.T.Addr)
	open, err := openResolver(s.T.Addr)
	switch {
	case err != nil:
		e.status("sin respuesta DNS en 53/udp (bien, o filtrado)")
	case open:
		e.find(model.Finding{
			Title: "Resolver DNS abierto en 53/udp", Severity: model.High, Port: 53,
			Detail:      "El servidor resuelve nombres arbitrarios para cualquiera en internet: se usa para ataques DDoS por amplificación y puede acabar en listas de bloqueo.",
			Evidence:    "dig @" + s.T.Addr.String() + " google.com → respuesta recursiva",
			Remediation: "Pi-hole: Settings → DNS → Interface settings → «Allow only local requests» (o «Respond only on interface …»). dnsmasq: `local-service` o `interface=eth0`. unbound: `access-control: 0.0.0.0/0 refuse` y permitir solo tu LAN. Bloquea 53/udp y 53/tcp entrantes en el router.",
			Refs:        []string{"https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks"},
		})
	default:
		e.status("DNS responde pero no recursa (correcto)")
	}
}
