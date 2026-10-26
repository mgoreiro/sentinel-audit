package scan

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"sentinel/internal/model"
)

func (s *Scan) tlsDial(ctx context.Context, port int, cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 4 * time.Second}
	c, err := d.DialContext(ctx, "tcp", s.addr(port))
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(6 * time.Second))
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

func checkTLS(ctx context.Context, s *Scan, e emitter) {
	ports := s.TLSPorts()
	if len(ports) == 0 {
		e.status("sin puertos TLS")
		return
	}
	var wg sync.WaitGroup
	for _, pi := range ports {
		wg.Add(1)
		go func(pi PortInfo) {
			defer wg.Done()
			e.status("analizando TLS en %d/tcp…", pi.Port)
			tlsProtocols(ctx, s, e, pi.Port)
			tlsCiphers(ctx, s, e, pi.Port)
			tlsCert(ctx, s, e, pi.Port)
		}(pi)
	}
	wg.Wait()
	e.status("%d puertos TLS analizados", len(ports))
}

func tlsProtocols(ctx context.Context, s *Scan, e emitter, port int) {
	versions := []struct {
		v    uint16
		name string
	}{{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}, {tls.VersionTLS12, "TLS 1.2"}, {tls.VersionTLS13, "TLS 1.3"}}
	ok := map[string]bool{}
	for _, v := range versions {
		cfg := &tls.Config{InsecureSkipVerify: true, ServerName: s.sni(), MinVersion: v.v, MaxVersion: v.v}
		if c, err := s.tlsDial(ctx, port, cfg); err == nil {
			c.Close()
			ok[v.name] = true
		}
	}
	for _, old := range []string{"TLS 1.0", "TLS 1.1"} {
		if ok[old] {
			e.find(model.Finding{
				Title: fmt.Sprintf("%s habilitado en %d/tcp", old, port), Severity: model.Medium, Port: port,
				Detail:      "Protocolo obsoleto (RFC 8996), vulnerable a ataques como BEAST/POODLE-TLS y rechazado por navegadores y PCI-DSS.",
				Remediation: "nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. Caddy: `protocols tls1.2 tls1.3`. Recarga el servicio y reevalúa. Configuración de referencia: Mozilla SSL Config Generator (Intermediate).",
				Refs:        []string{"https://ssl-config.mozilla.org/"},
			})
		}
	}
	if !ok["TLS 1.2"] && !ok["TLS 1.3"] {
		e.find(model.Finding{
			Title: fmt.Sprintf("El servidor en %d/tcp no admite TLS 1.2 ni 1.3", port), Severity: model.High, Port: port,
			Remediation: "Actualiza OpenSSL/nginx y fija `ssl_protocols TLSv1.2 TLSv1.3;`.",
		})
	} else if !ok["TLS 1.3"] {
		e.find(model.Finding{
			Title: fmt.Sprintf("TLS 1.3 no disponible en %d/tcp", port), Severity: model.Low, Port: port,
			Remediation: "Habilita `ssl_protocols TLSv1.2 TLSv1.3;` (requiere nginx ≥ 1.13 con OpenSSL ≥ 1.1.1).",
		})
	}
}

func tlsCiphers(ctx context.Context, s *Scan, e emitter, port int) {
	var ids []uint16
	for _, cs := range tls.InsecureCipherSuites() {
		ids = append(ids, cs.ID)
	}
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: s.sni(), MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, CipherSuites: ids}
	c, err := s.tlsDial(ctx, port, cfg)
	if err != nil {
		return
	}
	name := tls.CipherSuiteName(c.ConnectionState().CipherSuite)
	c.Close()
	e.find(model.Finding{
		Title: fmt.Sprintf("Suite de cifrado débil aceptada en %d/tcp", port), Severity: model.Medium, Port: port,
		Detail:      "El servidor negocia suites sin forward secrecy o con RC4/3DES/CBC-SHA1.",
		Evidence:    name,
		Remediation: "nginx: `ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;` y `ssl_prefer_server_ciphers off;`.",
		Refs:        []string{"https://ssl-config.mozilla.org/"},
	})
}

func tlsCert(ctx context.Context, s *Scan, e emitter, port int) {
	c, err := s.tlsDial(ctx, port, &tls.Config{InsecureSkipVerify: true, ServerName: s.sni()})
	if err != nil {
		return
	}
	certs := c.ConnectionState().PeerCertificates
	c.Close()
	if len(certs) == 0 {
		return
	}
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, ic := range certs[1:] {
		inter.AddCert(ic)
	}
	opts := x509.VerifyOptions{Intermediates: inter}
	if !s.T.IsIP {
		opts.DNSName = s.T.Host
	}
	_, verr := leaf.Verify(opts)

	var (
		unknown  x509.UnknownAuthorityError
		hostErr  x509.HostnameError
		invalid  x509.CertificateInvalidError
		selfSign = leaf.Issuer.String() == leaf.Subject.String()
	)
	switch {
	case verr == nil:
	case errors.As(verr, &unknown) && selfSign:
		e.find(model.Finding{
			Title: fmt.Sprintf("Certificado autofirmado en %d/tcp", port), Severity: model.Medium, Port: port,
			Detail:      "Los clientes no pueden verificar la identidad del servidor; los usuarios se acostumbran a ignorar la advertencia, lo que facilita ataques MITM.",
			Evidence:    "Subject: " + leaf.Subject.String(),
			Remediation: "Emite un certificado de Let's Encrypt (`certbot --nginx -d tu.dominio` o Caddy automático). Para servicios solo-LAN, usa tu propia CA y distribúyela a los clientes.",
		})
	case errors.As(verr, &unknown):
		e.find(model.Finding{
			Title: fmt.Sprintf("Cadena de certificados no confiable en %d/tcp", port), Severity: model.Medium, Port: port,
			Detail:      "Falta el certificado intermedio o la CA no es de confianza pública.",
			Evidence:    verr.Error(),
			Remediation: "Sirve `fullchain.pem` (hoja + intermedios) en `ssl_certificate`, no solo `cert.pem`.",
		})
	case errors.As(verr, &hostErr):
		e.find(model.Finding{
			Title: fmt.Sprintf("El certificado en %d/tcp no coincide con %s", port, s.T.Host), Severity: model.Medium, Port: port,
			Evidence:    verr.Error(),
			Remediation: "Emite el certificado incluyendo este nombre en el SAN, o configura el `server_name` correcto para que SNI sirva el certificado adecuado.",
		})
	case errors.As(verr, &invalid) && invalid.Reason == x509.Expired:
		// reported below with the expiry details
	default:
		e.find(model.Finding{
			Title: fmt.Sprintf("Certificado no válido en %d/tcp", port), Severity: model.Medium, Port: port, Evidence: verr.Error(),
			Remediation: "Revisa la cadena y las fechas del certificado (`openssl s_client -connect host:puerto -showcerts`).",
		})
	}

	left := time.Until(leaf.NotAfter)
	switch {
	case left < 0:
		e.find(model.Finding{
			Title: fmt.Sprintf("Certificado caducado en %d/tcp", port), Severity: model.High, Port: port,
			Evidence:    "Caducó el " + leaf.NotAfter.Format("2006-01-02"),
			Remediation: "Renueva ya: `certbot renew --force-renewal` y recarga nginx. Automatiza con el timer de certbot o Caddy.",
		})
	case left < 14*24*time.Hour:
		e.find(model.Finding{
			Title: fmt.Sprintf("Certificado a punto de caducar en %d/tcp (%d días)", port, int(left.Hours()/24)), Severity: model.Medium, Port: port,
			Evidence:    "Caduca el " + leaf.NotAfter.Format("2006-01-02"),
			Remediation: "Comprueba que la renovación automática funciona: `certbot renew --dry-run` y `systemctl list-timers | grep certbot`.",
		})
	}

	if k, ok := leaf.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
		e.find(model.Finding{
			Title: fmt.Sprintf("Clave RSA débil (%d bits) en %d/tcp", k.N.BitLen(), port), Severity: model.High, Port: port,
			Remediation: "Regenera el certificado con RSA ≥ 2048 bits o ECDSA P-256.",
		})
	}
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.MD5WithRSA, x509.ECDSAWithSHA1:
		e.find(model.Finding{
			Title: fmt.Sprintf("Certificado firmado con algoritmo débil en %d/tcp", port), Severity: model.Medium, Port: port,
			Evidence:    leaf.SignatureAlgorithm.String(),
			Remediation: "Reemite el certificado con SHA-256 o superior.",
		})
	}

	e.find(model.Finding{
		Title: fmt.Sprintf("Certificado en %d/tcp: %s", port, leaf.Subject.CommonName), Severity: model.Info, Port: port,
		Evidence: fmt.Sprintf("Emisor: %s\nVálido hasta: %s\nSAN: %s", leaf.Issuer.CommonName, leaf.NotAfter.Format("2006-01-02"), strings.Join(leaf.DNSNames, ", ")),
	})
}
