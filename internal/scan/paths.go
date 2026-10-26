package scan

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"sentinel/internal/model"
)

type pathRule struct {
	Path  string
	Sev   model.Severity
	Title string
	Match func(body string) bool
	Fix   string
}

func has(subs ...string) func(string) bool {
	return func(b string) bool {
		for _, s := range subs {
			if strings.Contains(b, s) {
				return true
			}
		}
		return false
	}
}

func prefix(p string) func(string) bool {
	return func(b string) bool { return strings.HasPrefix(strings.TrimSpace(b), p) }
}

func re(expr string) func(string) bool {
	r := regexp.MustCompile(expr)
	return r.MatchString
}

const fixHide = "Bloquea el acceso en nginx: `location ~ /\\.(?!well-known) { deny all; return 404; }`. " +
	"Elimina el fichero del directorio publicado (y del repositorio/imagen) y rota cualquier secreto que contuviera."

var pathRules = []pathRule{
	{"/.git/HEAD", model.High, "Repositorio .git expuesto", prefix("ref:"), "Permite reconstruir el código fuente completo y encontrar credenciales en el historial. " + fixHide},
	{"/.git/config", model.High, "Configuración .git expuesta", has("[core]", "[remote"), fixHide},
	{"/.env", model.Critical, "Fichero .env accesible", re(`(?m)^[A-Z][A-Z0-9_]+=`), "Contiene secretos (BBDD, claves API). Rótalos todos AHORA. " + fixHide},
	{"/.env.local", model.Critical, "Fichero .env.local accesible", re(`(?m)^[A-Z][A-Z0-9_]+=`), "Rota todos los secretos. " + fixHide},
	{"/.env.production", model.Critical, "Fichero .env.production accesible", re(`(?m)^[A-Z][A-Z0-9_]+=`), "Rota todos los secretos. " + fixHide},
	{"/.DS_Store", model.Medium, ".DS_Store expuesto", prefix("\x00\x00\x00\x01Bud1"), "Revela nombres de ficheros del directorio. " + fixHide},
	{"/.htpasswd", model.High, ".htpasswd expuesto", re(`(?m)^[\w.-]+:(\$|\{SHA\})`), "Hashes de contraseñas descargables. " + fixHide},
	{"/.svn/entries", model.Medium, "Repositorio SVN expuesto", re(`^\d+\s`), fixHide},
	{"/.aws/credentials", model.Critical, "Credenciales AWS expuestas", has("aws_access_key_id"), "Revoca las claves en IAM y rótalas. " + fixHide},
	{"/id_rsa", model.Critical, "Clave privada SSH expuesta", has("PRIVATE KEY"), "Regenera el par de claves y elimina la antigua de todos los `authorized_keys`."},
	{"/backup.zip", model.High, "Backup descargable (backup.zip)", prefix("PK"), "Mueve los backups fuera del webroot y no los dejes en directorios servidos."},
	{"/backup.tar.gz", model.High, "Backup descargable (backup.tar.gz)", prefix("\x1f\x8b"), "Mueve los backups fuera del webroot."},
	{"/backup.sql", model.High, "Volcado SQL descargable (backup.sql)", has("CREATE TABLE", "INSERT INTO"), "Mueve los volcados fuera del webroot y cambia las contraseñas que contuviera."},
	{"/dump.sql", model.High, "Volcado SQL descargable (dump.sql)", has("CREATE TABLE", "INSERT INTO"), "Mueve los volcados fuera del webroot."},
	{"/db.sql", model.High, "Volcado SQL descargable (db.sql)", has("CREATE TABLE", "INSERT INTO"), "Mueve los volcados fuera del webroot."},
	{"/phpinfo.php", model.Medium, "phpinfo() expuesto", has("PHP Version", "phpinfo()"), "Borra el fichero; revela rutas, módulos y variables de entorno."},
	{"/server-status", model.Medium, "Apache server-status accesible", has("Apache Server Status"), "Restringe `<Location /server-status>` a `Require ip 127.0.0.1`."},
	{"/nginx_status", model.Low, "nginx stub_status accesible", has("Active connections"), "Restringe el `location` con `allow 127.0.0.1; deny all;`."},
	{"/wp-config.php.bak", model.Critical, "Copia de wp-config.php", has("DB_PASSWORD"), "Elimínala, cambia la contraseña de BBDD y las claves/salts de WordPress."},
	{"/docker-compose.yml", model.High, "docker-compose.yml accesible", has("services:"), "Revela imágenes, puertos y a menudo secretos. " + fixHide},
	{"/actuator/env", model.High, "Spring Boot Actuator /env expuesto", has("propertySources"), "Desactiva endpoints sensibles: `management.endpoints.web.exposure.include=health`."},
	{"/metrics", model.Medium, "Métricas Prometheus accesibles", has("# HELP", "# TYPE"), "Publica las métricas solo en la red interna o con `allow`/`auth_basic` en nginx."},
}

var autoindexDirs = []string{"/", "/files/", "/backup/", "/backups/", "/uploads/", "/downloads/", "/media/", "/data/", "/logs/"}

func checkPaths(ctx context.Context, s *Scan, e emitter) {
	ports := s.HTTPPorts()
	if len(ports) == 0 {
		e.status("sin servicios web")
		return
	}
	var wg sync.WaitGroup
	for _, pi := range ports {
		sem := make(chan struct{}, 6)
		probe := func(f func()) {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				f()
			}()
		}
		e.status("sondeando rutas sensibles en %d/tcp…", pi.Port)
		for _, rule := range pathRules {
			rule := rule
			probe(func() {
				r := s.get(ctx, pi, "GET", rule.Path, nil)
				if r.Err != nil || r.Status != 200 || !rule.Match(r.Body) {
					return
				}
				e.find(model.Finding{
					Title: fmt.Sprintf("%s (%d/tcp)", rule.Title, pi.Port), Severity: rule.Sev, Port: pi.Port,
					Detail:      "Cualquiera puede descargar " + rule.Path + " sin autenticación.",
					Evidence:    fmt.Sprintf("GET %s → 200 (%d bytes)", rule.Path, len(r.Body)),
					Remediation: rule.Fix,
				})
			})
		}
		for _, d := range autoindexDirs {
			d := d
			probe(func() {
				r := s.get(ctx, pi, "GET", d, nil)
				if r.Err == nil && r.Status == 200 && (strings.Contains(r.Body, "<title>Index of ") || strings.Contains(r.Body, "<h1>Index of ")) {
					e.find(model.Finding{
						Title: fmt.Sprintf("Listado de directorio activo en %s (%d/tcp)", d, pi.Port), Severity: model.Medium, Port: pi.Port,
						Detail:      "El servidor muestra el contenido del directorio; permite descubrir y descargar ficheros no enlazados.",
						Evidence:    "GET " + d + " → «Index of " + d + "»",
						Remediation: "nginx: `autoindex off;` en el `location`/`server` (es el valor por defecto; búscalo con `grep -r autoindex /etc/nginx`). Apache: `Options -Indexes`.",
					})
				}
			})
		}
	}
	wg.Wait()
}
