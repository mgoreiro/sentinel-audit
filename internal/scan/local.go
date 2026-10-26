package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"sentinel/internal/model"
)

type inspect struct {
	Name       string `json:"Name"`
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		NetworkMode string   `json:"NetworkMode"`
		CapAdd      []string `json:"CapAdd"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source string `json:"Source"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

// checkLocalDocker audits the Docker host this tool runs on (not remote).
func checkLocalDocker(ctx context.Context, s *Scan, e emitter) {
	if !have("docker") {
		e.status("docker no está instalado")
		return
	}
	ids, err := exec.CommandContext(ctx, "docker", "ps", "-q").Output()
	if err != nil {
		e.status("no se pudo ejecutar docker ps (¿daemon parado o sin permisos?)")
		return
	}
	idList := strings.Fields(string(ids))
	if len(idList) == 0 {
		e.status("sin contenedores en ejecución")
		return
	}
	out, err := exec.CommandContext(ctx, "docker", append([]string{"inspect"}, idList...)...).Output()
	if err != nil {
		e.status("docker inspect falló")
		return
	}
	var cs []inspect
	if json.Unmarshal(out, &cs) != nil {
		return
	}
	for _, c := range cs {
		name := strings.TrimPrefix(c.Name, "/")
		if c.HostConfig.Privileged {
			e.find(model.Finding{
				Title: "Contenedor privilegiado: " + name, Severity: model.High,
				Detail:      "`--privileged` da al contenedor acceso casi total al host; un fallo en la app equivale a root en la máquina.",
				Remediation: "Quita `privileged: true`. Añade solo las capacidades necesarias (`cap_add:`) o dispositivos concretos (`devices:`).",
			})
		}
		if c.HostConfig.NetworkMode == "host" {
			e.find(model.Finding{
				Title: "Contenedor en red host: " + name, Severity: model.Medium,
				Detail:      "Con `network_mode: host` todos sus puertos quedan publicados en el host, saltándose la configuración de `ports:`.",
				Remediation: "Usa una red bridge y publica solo lo necesario enlazando a `127.0.0.1`.",
			})
		}
		for _, m := range c.Mounts {
			if strings.HasSuffix(m.Source, "docker.sock") {
				e.find(model.Finding{
					Title: "docker.sock montado en " + name, Severity: model.High,
					Detail:      "Quien comprometa este contenedor puede crear otros privilegiados y tomar el host.",
					Remediation: "Evítalo; si es imprescindible (Traefik, Watchtower, Portainer) monta `:ro` y usa un proxy de socket como `tecnativa/docker-socket-proxy` limitando la API.",
				})
			}
		}
		for port, binds := range c.NetworkSettings.Ports {
			for _, b := range binds {
				if b.HostIP == "0.0.0.0" || b.HostIP == "::" || b.HostIP == "" {
					p := 0
					fmt.Sscanf(b.HostPort, "%d", &p)
					e.find(model.Finding{
						Title: fmt.Sprintf("%s publica %s en todas las interfaces (%s:%s)", name, port, orAny(b.HostIP), b.HostPort), Severity: model.Medium, Port: p,
						Detail:      "Docker inserta sus propias reglas de iptables y salta ufw/firewalld: el puerto es accesible desde fuera aunque el firewall diga lo contrario.",
						Remediation: fmt.Sprintf("En docker-compose: `ports: [\"127.0.0.1:%s:%s\"]` y que el reverse proxy lo alcance en loopback o por red Docker interna. Para firewall robusto usa la cadena DOCKER-USER.", b.HostPort, strings.Split(port, "/")[0]),
					})
				}
			}
		}
	}
	e.status("%d contenedores revisados", len(cs))
}

func orAny(s string) string {
	if s == "" {
		return "0.0.0.0"
	}
	return s
}
