# sentinel

TUI (Go + Bubble Tea) para auditar la superficie expuesta de un servidor **propio o autorizado**.
Ejecútalo desde fuera de tu LAN (4G o un VPS) para ver lo que ve un atacante.

```bash
go build -o sentinel .
./sentinel                       # TUI interactiva
./sentinel --full midominio.com  # los 65535 puertos TCP
./sentinel --plain --yes --md informe.md --json informe.json midominio.com
sudo ./sentinel ...              # añade escaneo UDP (nmap -sU top 50)
```

Salida `--plain`: código 3 si hay hallazgos High/Critical.

## Checks
- Nativos: puertos TCP + fingerprint, TLS (protocolos, suites, certificado), cabeceras HTTP/HSTS/cookies/CORS/TRACE,
  rutas sensibles (`.git`, `.env`, backups, autoindex), paneles (Guacamole, Pi-hole, Threadfin, rTorrent, Portainer…),
  resolver DNS abierto, banner SSH (regreSSHion), crt.sh, Shodan (`SHODAN_API_KEY`), Docker local (`--local`).
- Opcionales si están instalados: `nmap` (versiones, ssh-auth-methods, vulners, UDP), `nuclei`, `testssl.sh`.

Cada hallazgo incluye evidencia y una solución concreta (snippets de nginx/sshd/Docker).
Manual (no automatizable): UPnP/port-forwarding del router, 2FA de la cuenta DNS, registro abierto en Immich/PinePods.
