package scan

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"sentinel/internal/model"
)

var versionedRe = regexp.MustCompile(`[A-Za-z][\w.-]*/\d+(\.\d+)+`)

func checkHTTP(ctx context.Context, s *Scan, e emitter) {
	ports := s.HTTPPorts()
	if len(ports) == 0 {
		e.status("sin servicios web")
		return
	}
	hasTLS := len(s.TLSPorts()) > 0
	var wg sync.WaitGroup
	for _, pi := range ports {
		wg.Add(1)
		go func(pi PortInfo) {
			defer wg.Done()
			e.status("revisando %d/tcp…", pi.Port)
			r := s.get(ctx, pi, "GET", "/", nil)
			if r.Err != nil {
				e.status("%d/tcp: %v", pi.Port, r.Err)
				return
			}
			if pi.TLS {
				httpsHeaders(e, pi.Port, r)
			} else {
				plainHTTP(e, pi.Port, r, hasTLS)
			}
			commonHeaders(e, pi, r)
			cookies(e, pi, r)
			cors(ctx, s, e, pi)
			trace(ctx, s, e, pi)
		}(pi)
	}
	wg.Wait()
}

func plainHTTP(e emitter, port int, r resp, hasTLS bool) {
	loc := r.Header.Get("Location")
	if r.Status >= 300 && r.Status < 400 && strings.HasPrefix(strings.ToLower(loc), "https://") {
		return
	}
	if hasTLS {
		e.find(model.Finding{
			Title: fmt.Sprintf("HTTP en %d/tcp no redirige a HTTPS", port), Severity: model.Medium, Port: port,
			Detail:      "Los clientes que entren por HTTP envían credenciales y cookies en claro y son vulnerables a degradación/MITM.",
			Evidence:    fmt.Sprintf("GET / → %d %s", r.Status, loc),
			Remediation: "nginx: `server { listen 80; server_name _; return 301 https://$host$request_uri; }`",
		})
		return
	}
	e.find(model.Finding{
		Title: fmt.Sprintf("Servicio web sin TLS en %d/tcp", port), Severity: model.Medium, Port: port,
		Detail:      "El tráfico, incluidas contraseñas y cookies, viaja sin cifrar.",
		Evidence:    fmt.Sprintf("GET / → %d", r.Status),
		Remediation: "Publica el servicio tras un reverse proxy con HTTPS (nginx + certbot, o Caddy con certificados automáticos) y redirige el 80 al 443.",
	})
}

func httpsHeaders(e emitter, port int, r resp) {
	if r.Header.Get("Strict-Transport-Security") == "" {
		e.find(model.Finding{
			Title: fmt.Sprintf("Falta HSTS en %d/tcp", port), Severity: model.Medium, Port: port,
			Detail:      "Sin Strict-Transport-Security el navegador puede ser forzado a usar HTTP (sslstrip).",
			Remediation: "nginx: `add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;`. Añade `preload` solo cuando todos los subdominios sean HTTPS.",
			Refs:        []string{"https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"},
		})
	}
}

func commonHeaders(e emitter, pi PortInfo, r resp) {
	h := r.Header
	port := pi.Port
	if h.Get("X-Content-Type-Options") == "" {
		e.find(model.Finding{
			Title: fmt.Sprintf("Falta X-Content-Type-Options en %d/tcp", port), Severity: model.Low, Port: port,
			Remediation: "nginx: `add_header X-Content-Type-Options \"nosniff\" always;`",
		})
	}
	csp := h.Get("Content-Security-Policy")
	if h.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		e.find(model.Finding{
			Title: fmt.Sprintf("Sin protección contra clickjacking en %d/tcp", port), Severity: model.Low, Port: port,
			Detail:      "La página puede incrustarse en un iframe ajeno.",
			Remediation: "nginx: `add_header X-Frame-Options \"SAMEORIGIN\" always;` o CSP `frame-ancestors 'self'`. Si es un panel (Guacamole, Pi-hole) valora `DENY`.",
		})
	}
	if csp == "" {
		e.find(model.Finding{
			Title: fmt.Sprintf("Falta Content-Security-Policy en %d/tcp", port), Severity: model.Low, Port: port,
			Detail:      "CSP mitiga XSS limitando de dónde se cargan scripts y recursos.",
			Remediation: "Empieza en modo informe: `add_header Content-Security-Policy-Report-Only \"default-src 'self'\" always;`, ajusta y pasa a enforcing. Ojo: apps como Immich o Guacamole pueden necesitar `'unsafe-inline'`/`blob:`.",
		})
	}
	if h.Get("Referrer-Policy") == "" {
		e.find(model.Finding{
			Title: fmt.Sprintf("Falta Referrer-Policy en %d/tcp", port), Severity: model.Info, Port: port,
			Remediation: "nginx: `add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;`",
		})
	}
	if v := h.Get("Server"); versionedRe.MatchString(v) {
		e.find(model.Finding{
			Title: fmt.Sprintf("La cabecera Server revela la versión en %d/tcp", port), Severity: model.Low, Port: port,
			Detail:      "Facilita al atacante buscar exploits para esa versión concreta.",
			Evidence:    "Server: " + v,
			Remediation: "nginx: `server_tokens off;` en `http {}`. Para ocultar el nombre completo usa el módulo headers-more (`more_clear_headers Server;`). Apache: `ServerTokens Prod` y `ServerSignature Off`.",
		})
	}
	if v := h.Get("X-Powered-By"); v != "" {
		e.find(model.Finding{
			Title: fmt.Sprintf("X-Powered-By revela la tecnología en %d/tcp", port), Severity: model.Low, Port: port,
			Evidence:    "X-Powered-By: " + v,
			Remediation: "nginx: `proxy_hide_header X-Powered-By;`. PHP: `expose_php = Off`. Express: `app.disable('x-powered-by')`.",
		})
	}
}

func cookies(e emitter, pi PortInfo, r resp) {
	var bad []string
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		var miss []string
		if pi.TLS && !c.Secure {
			miss = append(miss, "Secure")
		}
		if !c.HttpOnly {
			miss = append(miss, "HttpOnly")
		}
		if c.SameSite == http.SameSiteDefaultMode {
			miss = append(miss, "SameSite")
		}
		if len(miss) > 0 {
			bad = append(bad, fmt.Sprintf("%s: falta %s", c.Name, strings.Join(miss, ", ")))
		}
	}
	if len(bad) > 0 {
		e.find(model.Finding{
			Title: fmt.Sprintf("Cookies sin atributos de seguridad en %d/tcp", pi.Port), Severity: model.Low, Port: pi.Port,
			Evidence:    strings.Join(bad, "\n"),
			Remediation: "En el proxy: `proxy_cookie_flags ~ Secure HttpOnly SameSite=Lax;` (nginx ≥ 1.19.3), o configúralo en la aplicación.",
		})
	}
}

func cors(ctx context.Context, s *Scan, e emitter, pi PortInfo) {
	const origin = "https://evil.example"
	r := s.get(ctx, pi, "GET", "/", map[string]string{"Origin": origin})
	if r.Err != nil {
		return
	}
	acao, acac := r.Header.Get("Access-Control-Allow-Origin"), r.Header.Get("Access-Control-Allow-Credentials")
	if (acao == origin || acao == "*") && strings.EqualFold(acac, "true") {
		e.find(model.Finding{
			Title: fmt.Sprintf("CORS permite cualquier origen con credenciales en %d/tcp", pi.Port), Severity: model.High, Port: pi.Port,
			Detail:      "Una web maliciosa puede leer respuestas autenticadas de este servicio con la sesión del usuario.",
			Evidence:    fmt.Sprintf("Origin: %s → ACAO: %s, ACAC: %s", origin, acao, acac),
			Remediation: "Usa una lista blanca de orígenes concretos; nunca reflejes `Origin` ni combines `*` con `Allow-Credentials: true`.",
		})
	}
}

func trace(ctx context.Context, s *Scan, e emitter, pi PortInfo) {
	r := s.get(ctx, pi, "TRACE", "/", nil)
	if r.Err == nil && r.Status == 200 && strings.Contains(r.Body, "TRACE") {
		e.find(model.Finding{
			Title: fmt.Sprintf("Método HTTP TRACE habilitado en %d/tcp", pi.Port), Severity: model.Low, Port: pi.Port,
			Remediation: "Apache: `TraceEnable off`. nginx lo rechaza por defecto; revisa el proxy aguas arriba.",
		})
	}
}
