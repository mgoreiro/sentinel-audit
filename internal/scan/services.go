package scan

import (
	"context"
	"fmt"
	"regexp"
	"sync"

	"sentinel/internal/model"
)

type fingerprint struct {
	Name  string
	Path  string
	Match *regexp.Regexp
	Sev   model.Severity
	Why   string
	Fix   string
}

var fingerprints = []fingerprint{
	{"Apache Guacamole", "/guacamole/", regexp.MustCompile(`(?i)<title>[^<]*guacamole|guac-login|Apache Guacamole`), model.High,
		"Pasarela de escritorio remoto accesible desde internet: es el servicio más crítico de la lista (un login comprometido = acceso a tus máquinas).",
		"1) Cambia/elimina el usuario `guacadmin` (pass por defecto `guacadmin`). 2) Activa TOTP: extensión `guacamole-auth-totp` (en Docker: `TOTP_ENABLED=true`). 3) Verifica que PostgreSQL y guacd no estén publicados (`docker ps`). 4) Mejor aún: tras VPN o con `allow <IP>; deny all;`/mTLS en el `location /guacamole/` de nginx. 5) fail2ban sobre los logs de login."},
	{"Pi-hole (panel)", "/admin/", regexp.MustCompile(`(?i)pi-hole`), model.High,
		"El panel de Pi-hole no debe ser accesible desde internet.",
		"Restringe `/admin` con `allow <LAN/VPN>; deny all;` o elimina el proxy hacia él. En Pi-hole: define contraseña fuerte y escucha DNS solo en la LAN."},
	{"Threadfin", "/web/", regexp.MustCompile(`(?i)threadfin`), model.High,
		"Threadfin no incluye autenticación efectiva: cualquiera puede ver/modificar listas y configuración.",
		"Añade `auth_basic` (htpasswd), mTLS o una allowlist de IPs en el `location` de nginx; no publiques el puerto 34400 directamente."},
	{"ruTorrent / rTorrent", "/", regexp.MustCompile(`(?i)ruTorrent`), model.High,
		"Cliente de torrents sin autenticación propia; ruTorrent permite ejecutar plugins y leer ficheros.",
		"`auth_basic` o mTLS en nginx, y asegúrate de que el socket/puerto SCGI (`/RPC2`, 5000) solo escucha en 127.0.0.1 o en un socket Unix."},
	{"rTorrent XML-RPC", "/RPC2", regexp.MustCompile(`(?i)xml-?rpc|methodResponse|SCGI`), model.High,
		"XML-RPC de rTorrent accesible: permite ejecutar comandos (`execute.*`) en el servidor.",
		"Protege `/RPC2` con `auth_basic`/allowlist y no expongas el puerto SCGI directamente."},
	{"Portainer", "/", regexp.MustCompile(`(?i)<title>Portainer`), model.High,
		"Portainer da control total de Docker (equivale a root en el host).",
		"Solo por VPN/allowlist, 2FA/OAuth y contraseña fuerte; el primer admin debe crearse antes de exponerlo."},
	{"Docker Engine API", "/version", regexp.MustCompile(`"ApiVersion"\s*:`), model.Critical,
		"API de Docker sin autenticación: control root total del host.",
		"Cierra el puerto, usa el socket Unix o TLS mutuo (`--tlsverify`)."},
	{"Elasticsearch", "/", regexp.MustCompile(`You Know, for Search`), model.High,
		"Elasticsearch accesible sin autenticación.",
		"Activa `xpack.security.enabled: true` y no lo publiques en internet."},
	{"Immich", "/api/server/ping", regexp.MustCompile(`"res"\s*:\s*"pong"`), model.Low,
		"Immich accesible públicamente (fotos privadas).",
		"Comprueba en Administración → Ajustes que el registro de usuarios está cerrado, usa contraseñas únicas/OAuth, publícalo solo vía HTTPS en el proxy y mantenlo actualizado (hay CVEs frecuentes)."},
	{"PinePods", "/", regexp.MustCompile(`(?i)pinepods`), model.Low,
		"PinePods accesible públicamente.",
		"Desactiva el auto-registro (`DISABLE_SELF_SERVICE_USERS`/ajustes de admin), cambia la contraseña por defecto y publícalo solo tras HTTPS."},
	{"Grafana", "/login", regexp.MustCompile(`(?i)grafana`), model.Medium,
		"Grafana accesible; las instalaciones sin cambiar `admin/admin` son comunes.",
		"Cambia la contraseña de admin, desactiva `allow_sign_up` y el acceso anónimo, o ponlo tras VPN."},
	{"Prometheus", "/graph", regexp.MustCompile(`(?i)<title>Prometheus`), model.High,
		"Prometheus sin autenticación filtra topología y métricas.",
		"Ponlo en la red interna o con `basic_auth` vía `--web.config.file`."},
	{"phpMyAdmin", "/phpmyadmin/", regexp.MustCompile(`(?i)phpMyAdmin`), model.High,
		"phpMyAdmin es un objetivo habitual de fuerza bruta y exploits.",
		"Retíralo de producción o restríngelo por IP/VPN y añade una capa extra de `auth_basic`."},
	{"Jenkins", "/login", regexp.MustCompile(`(?i)jenkins`), model.High,
		"Jenkins permite ejecutar código; histórico de RCE.",
		"Tras VPN, con autenticación obligatoria y sin registro de usuarios; mantén el core y plugins actualizados."},
	{"Jellyfin", "/System/Info/Public", regexp.MustCompile(`"ProductName"\s*:\s*"Jellyfin`), model.Info,
		"Jellyfin accesible públicamente (la ruta revela la versión sin login).",
		"Publícalo solo vía HTTPS en el proxy, mantén la versión al día y desactiva usuarios sin contraseña."},
}

func checkServices(ctx context.Context, s *Scan, e emitter) {
	ports := s.HTTPPorts()
	if len(ports) == 0 {
		e.status("sin servicios web")
		return
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, pi := range ports {
		for _, fp := range fingerprints {
			wg.Add(1)
			sem <- struct{}{}
			go func(pi PortInfo, fp fingerprint) {
				defer wg.Done()
				defer func() { <-sem }()
				r := s.get(ctx, pi, "GET", fp.Path, nil)
				if r.Err != nil || r.Status != 200 || !fp.Match.MatchString(r.Body) {
					return
				}
				e.find(model.Finding{
					Title: fmt.Sprintf("%s accesible sin autenticación previa en %d/tcp (%s)", fp.Name, pi.Port, fp.Path), Severity: fp.Sev, Port: pi.Port,
					Detail:      fp.Why,
					Evidence:    fmt.Sprintf("GET %s → 200", fp.Path),
					Remediation: fp.Fix,
				})
			}(pi, fp)
		}
	}
	wg.Wait()
}
