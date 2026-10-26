package scan

import (
	"fmt"
	"regexp"
	"strings"

	"sentinel/internal/model"
)

type portRule struct {
	Name string
	Sev  model.Severity
	Why  string
	Fix  string
}

const (
	fixDB = "Nunca publiques bases de datos ni brokers en internet. En Docker enlaza a loopback (`127.0.0.1:%[1]d:%[1]d`) o usa una red interna sin `ports:`; " +
		"elimina el port-forward del router (y revisa UPnP). Si necesitas acceso remoto, usa WireGuard/Tailscale o un túnel SSH."
	fixAdmin = "Panel de administración/remoto: no lo expongas directamente. Ponlo tras WireGuard/Tailscale, o en nginx con `allow <tu-IP>; deny all;`, mTLS o `auth_basic` + 2FA. " +
		"Cierra el puerto directo en el router y en Docker (`127.0.0.1:` en `ports:`)."
	fixRemoteDesktop = "Escritorio remoto expuesto: es el objetivo favorito de ransomware. Accede solo por VPN (WireGuard/Tailscale), activa NLA/2FA y limita intentos (fail2ban/CrowdSec)."
	fixCleartext     = "Protocolo sin cifrar: migra a su variante TLS (IMAPS 993, POP3S 995, SMTPS 465/587+STARTTLS, FTPS/SFTP) y cierra el puerto en claro."
)

var portKB = map[int]portRule{
	21:    {"FTP", model.High, "FTP transmite usuario y contraseña en claro y suele permitir login anónimo.", "Sustituye FTP por SFTP/FTPS. Si debe existir, restringe por IP/VPN, desactiva `anonymous_enable` y fuerza TLS."},
	22:    {"SSH", model.Low, "SSH expuesto a internet recibe fuerza bruta constante.", "En `/etc/ssh/sshd_config`: `PasswordAuthentication no`, `PermitRootLogin no`, `AllowUsers <tu-usuario>`. Añade fail2ban o CrowdSec, y mejor expónlo solo por VPN o en un puerto no estándar."},
	23:    {"Telnet", model.Critical, "Telnet es texto plano y trivial de interceptar.", "Desactiva telnetd y usa SSH. Cierra el puerto 23 en router y firewall."},
	25:    {"SMTP", model.Medium, "Un MTA expuesto puede ser open relay o fuente de spam si está mal configurado.", "Si no gestionas correo propio, ciérralo. Si sí, desactiva el relay abierto (`smtpd_relay_restrictions`) y exige STARTTLS + autenticación."},
	53:    {"DNS", model.Medium, "Servicio DNS accesible desde internet; puede ser un resolver abierto (amplificación DDoS).", "Pi-hole/dnsmasq/unbound: escucha solo en la LAN (`interface=` / `local-service`). Bloquea 53/tcp y 53/udp entrantes en el router."},
	80:    {"HTTP", model.Info, "", ""},
	110:   {"POP3", model.Medium, "POP3 sin cifrar.", fixCleartext},
	111:   {"rpcbind", model.High, "rpcbind expone servicios RPC/NFS y se usa para amplificación DDoS.", "Desactiva rpcbind (`systemctl disable --now rpcbind`) o filtra el puerto con el firewall."},
	135:   {"MS-RPC", model.High, "RPC de Windows expuesto.", "Bloquea 135/139/445 en el perímetro. Nunca deben ser accesibles desde internet."},
	139:   {"NetBIOS", model.High, "NetBIOS/SMB expuesto.", "Bloquea 135/139/445 en el perímetro."},
	143:   {"IMAP", model.Medium, "IMAP sin cifrar.", fixCleartext},
	389:   {"LDAP", model.High, "Directorio LDAP expuesto.", "Cierra el puerto, usa LDAPS y limita por origen/VPN."},
	443:   {"HTTPS", model.Info, "", ""},
	445:   {"SMB", model.Critical, "SMB expuesto a internet (EternalBlue, ransomware, fuerza bruta).", "Bloquea 445 en el router/firewall y desactiva SMBv1. Comparte ficheros solo por VPN."},
	465:   {"SMTPS", model.Info, "", ""},
	587:   {"Submission", model.Info, "", ""},
	873:   {"rsync", model.High, "rsync daemon expuesto; a menudo permite listar y leer módulos sin auth.", "Cierra el puerto y usa rsync sobre SSH."},
	993:   {"IMAPS", model.Info, "", ""},
	1433:  {"MSSQL", model.High, "SQL Server expuesto.", fixDB},
	1521:  {"Oracle", model.High, "Oracle DB expuesta.", fixDB},
	1883:  {"MQTT", model.Medium, "Broker MQTT expuesto, a menudo sin autenticación.", "Exige usuario/contraseña y TLS (8883), o déjalo solo en la LAN/VPN."},
	2049:  {"NFS", model.High, "NFS expuesto.", "Bloquea 2049 en el perímetro; exporta solo a IPs concretas de la LAN."},
	2375:  {"Docker API", model.Critical, "La API de Docker sin TLS da control root total del host.", "Elimina `-H tcp://0.0.0.0:2375` del daemon. Usa el socket Unix o TLS mutuo (2376) y cierra el puerto."},
	2376:  {"Docker API (TLS)", model.High, "API de Docker expuesta, aunque con TLS.", "Exige certificados de cliente y limita por IP/VPN."},
	2283:  {"Immich", model.Medium, "Immich publicado directamente (sin proxy TLS).", "Publica solo a través del reverse proxy con HTTPS, desactiva el registro abierto y activa 2FA/OAuth."},
	3000:  {"Dev server / Grafana", model.Low, "Servidor de desarrollo o Grafana.", fixAdmin},
	3306:  {"MySQL/MariaDB", model.High, "Base de datos expuesta.", fixDB},
	3389:  {"RDP", model.High, "RDP expuesto.", fixRemoteDesktop},
	4822:  {"guacd", model.High, "El daemon de Guacamole (guacd) no debe ser accesible desde fuera de la red Docker.", fixAdmin},
	5000:  {"SCGI/Flask/registry", model.Medium, "Puerto típico de rTorrent (SCGI), apps Flask y Docker registry; suelen carecer de autenticación.", "No publiques SCGI: déjalo en 127.0.0.1 o socket Unix y que nginx haga de proxy con `auth_basic`/allowlist."},
	5050:  {"sftp-web-manager", model.Medium, "Gestor web de ficheros expuesto directamente.", "Ponlo detrás de VPN o proxy con autenticación fuerte; revisa límite de intentos de login, CSRF y `sudoers` restringido."},
	5432:  {"PostgreSQL", model.High, "PostgreSQL expuesto.", fixDB},
	5672:  {"AMQP", model.Medium, "RabbitMQ expuesto.", fixDB},
	5900:  {"VNC", model.High, "VNC expuesto, normalmente con contraseña débil y sin cifrado.", fixRemoteDesktop},
	5901:  {"VNC", model.High, "VNC expuesto.", fixRemoteDesktop},
	5984:  {"CouchDB", model.High, "CouchDB expuesto.", fixDB},
	6000:  {"X11", model.High, "Servidor X11 expuesto.", "Desactiva `-listen tcp`; usa `ssh -X`."},
	6379:  {"Redis", model.High, "Redis expuesto; sin auth permite RCE vía CONFIG/SLAVEOF.", fixDB + " Define `requirepass`/ACLs y `protected-mode yes`."},
	8086:  {"InfluxDB", model.Medium, "InfluxDB expuesto.", fixDB},
	8096:  {"Jellyfin", model.Low, "Jellyfin publicado directamente.", "Publícalo solo vía proxy HTTPS y desactiva el descubrimiento/usuarios por defecto."},
	8443:  {"HTTPS alt", model.Info, "", ""},
	9000:  {"Portainer/PHP-FPM", model.Medium, "Portainer o PHP-FPM; ambos peligrosos si son accesibles.", fixAdmin},
	9090:  {"Prometheus/Cockpit", model.Medium, "Prometheus o Cockpit expuestos.", fixAdmin},
	9091:  {"Transmission/Authelia", model.Low, "Panel de descargas/autenticación.", fixAdmin},
	9200:  {"Elasticsearch", model.High, "Elasticsearch expuesto, normalmente sin auth.", fixDB + " Activa `xpack.security`."},
	9300:  {"Elasticsearch", model.High, "Transporte de Elasticsearch expuesto.", fixDB},
	9443:  {"Portainer", model.Medium, "Portainer expuesto.", fixAdmin},
	10000: {"Webmin", model.High, "Webmin expuesto (histórico de RCE).", fixAdmin},
	11211: {"Memcached", model.High, "Memcached expuesto (fuga de datos y amplificación DDoS).", fixDB + " Arranca con `-l 127.0.0.1` y `-U 0`."},
	15672: {"RabbitMQ mgmt", model.Medium, "Consola de RabbitMQ expuesta.", fixAdmin},
	21115: {"RustDesk (hbbs)", model.Medium, "Servidor RustDesk ID/rendezvous expuesto.", "Es esperable si usas RustDesk. Arranca hbbs/hbbr con `-k _` para forzar clave de servidor y no admitas conexiones sin cifrar."},
	21116: {"RustDesk (hbbs)", model.Medium, "Servidor RustDesk rendezvous expuesto.", "Fuerza clave con `-k _` y comprueba que la clave pública está distribuida a los clientes."},
	21117: {"RustDesk (hbbr)", model.Medium, "Relay RustDesk expuesto.", "Fuerza clave con `-k _`; limita el ancho de banda y considera VPN."},
	21118: {"RustDesk web", model.Medium, "Cliente web de RustDesk expuesto.", "Desactívalo si no lo usas."},
	21119: {"RustDesk web", model.Medium, "Cliente web de RustDesk expuesto.", "Desactívalo si no lo usas."},
	27017: {"MongoDB", model.Critical, "MongoDB expuesto; históricamente sin auth por defecto.", fixDB + " Activa `security.authorization: enabled`."},
	34400: {"Threadfin", model.High, "Threadfin no trae autenticación por defecto.", "Protégelo con `auth_basic`, mTLS o allowlist de IPs en nginx y no publiques el puerto directamente."},
}

var udpKB = map[int]portRule{
	53:    {"DNS", model.Medium, "DNS accesible desde internet.", "Escucha solo en la LAN y bloquea 53/udp en el router."},
	69:    {"TFTP", model.High, "TFTP sin autenticación.", "Desactiva TFTP o limítalo a la LAN."},
	123:   {"NTP", model.Low, "NTP expuesto (amplificación si permite monlist).", "En ntp.conf: `restrict default noquery nomodify notrap nopeer`; o usa chrony con `allow` solo para tu LAN."},
	161:   {"SNMP", model.High, "SNMP expuesto; community `public` filtra la configuración del equipo.", "Desactiva SNMP o usa SNMPv3 con auth+priv y filtra por origen."},
	1900:  {"UPnP/SSDP", model.High, "SSDP/UPnP accesible desde internet: indica router con UPnP mal configurado y permite amplificación.", "Desactiva UPnP en el router y revisa la tabla de port-forwards creada dinámicamente."},
	5353:  {"mDNS", model.Low, "mDNS accesible desde internet.", "Bloquea 5353/udp entrante."},
	11211: {"Memcached", model.High, "Memcached UDP (amplificación DDoS).", "Arranca con `-U 0` y `-l 127.0.0.1`."},
}

// portFinding builds the finding for an open TCP port from the knowledge base.
func portFinding(pi PortInfo) model.Finding {
	title := fmt.Sprintf("Puerto %d/tcp abierto", pi.Port)
	ev := strings.TrimSpace(pi.Banner)
	if r, ok := portKB[pi.Port]; ok {
		if r.Name != "" {
			title += ": " + r.Name
		}
		fix := r.Fix
		if strings.Contains(fix, "%[1]d") {
			fix = fmt.Sprintf(fix, pi.Port)
		}
		return model.Finding{Title: title, Severity: r.Sev, Port: pi.Port, Detail: r.Why, Evidence: ev, Remediation: fix}
	}
	name := pi.Service
	if name != "" {
		title += ": " + name
	}
	return model.Finding{
		Title: title, Severity: model.Info, Port: pi.Port, Evidence: ev,
		Detail:      "Puerto no habitual accesible desde internet.",
		Remediation: "Confirma que este servicio debe ser público. Si no, ciérralo en el router (port-forward/UPnP), en el firewall del host y en Docker (`127.0.0.1:` en `ports:`).",
	}
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// Enrich fills in generic remediation and references for findings that came
// from external tools without them.
func Enrich(f *model.Finding) {
	seen := map[string]bool{}
	for _, r := range f.Refs {
		seen[r] = true
	}
	for _, cve := range cveRe.FindAllString(f.Title+" "+f.Detail+" "+f.Evidence, 8) {
		ref := "https://nvd.nist.gov/vuln/detail/" + cve
		if !seen[ref] {
			f.Refs = append(f.Refs, ref)
			seen[ref] = true
		}
		if f.Remediation == "" {
			f.Remediation = "Actualiza el software afectado a la última versión estable (o aplica el parche del proveedor/distribución) y consulta el aviso de " + cve + ". Si no puedes parchear ya, restringe el acceso al servicio."
		}
	}
	if f.Remediation == "" {
		f.Remediation = "Revisa la documentación del servicio afectado y aplica la configuración segura recomendada; si no es imprescindible que sea público, restringe el acceso."
	}
}
