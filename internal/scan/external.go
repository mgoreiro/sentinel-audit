package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sentinel/internal/model"
)

// ---------- nmap ----------

type nmapRun struct {
	Hosts []struct {
		Ports []struct {
			Proto   string `xml:"protocol,attr"`
			ID      int    `xml:"portid,attr"`
			State   struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
			} `xml:"service"`
			Scripts []struct {
				ID     string `xml:"id,attr"`
				Output string `xml:"output,attr"`
			} `xml:"script"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

func runNmap(ctx context.Context, args ...string) (*nmapRun, string, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "nmap", append(args, "-oX", "-")...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, stderr.String(), err
	}
	var run nmapRun
	if xerr := xml.Unmarshal(out, &run); xerr != nil {
		return nil, stderr.String(), xerr
	}
	return &run, stderr.String(), nil
}

var vulnersRe = regexp.MustCompile(`(CVE-\d{4}-\d{4,7})\s+(\d+(?:\.\d+)?)`)

func checkNmap(ctx context.Context, s *Scan, e emitter) {
	ports := s.Ports()
	if len(ports) > 0 {
		var list []string
		for _, p := range ports {
			list = append(list, strconv.Itoa(p.Port))
		}
		e.status("nmap -sV sobre %d puertos abiertos…", len(ports))
		args := []string{"-sV", "--version-light", "-Pn", "-n", "-p", strings.Join(list, ","), "--script", "ssh-auth-methods,vulners", s.T.Addr.String()}
		cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
		run, errOut, err := runNmap(cctx, args...)
		if err != nil && strings.Contains(errOut, "NSE") { // vulners script not installed
			run, _, err = runNmap(cctx, "-sV", "--version-light", "-Pn", "-n", "-p", strings.Join(list, ","), "--script", "ssh-auth-methods", s.T.Addr.String())
		}
		cancel()
		if err != nil {
			e.status("nmap falló: %v", err)
		} else {
			nmapReport(s, e, run)
		}
	}
	if os.Geteuid() == 0 {
		e.status("nmap -sU sobre top 50 puertos UDP…")
		cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		run, _, err := runNmap(cctx, "-sU", "--top-ports", "50", "--open", "-Pn", "-n", "--max-retries", "1", s.T.Addr.String())
		cancel()
		if err == nil && run != nil {
			for _, h := range run.Hosts {
				for _, p := range h.Ports {
					if p.Proto != "udp" || !strings.HasPrefix(p.State.State, "open") {
						continue
					}
					r, ok := udpKB[p.ID]
					f := model.Finding{
						Title: fmt.Sprintf("Puerto %d/udp abierto: %s", p.ID, p.Service.Name), Severity: model.Info, Port: p.ID,
						Remediation: "Confirma que este servicio UDP debe ser público; si no, ciérralo en router y firewall.",
					}
					if ok {
						f.Title, f.Severity, f.Detail, f.Remediation = fmt.Sprintf("Puerto %d/udp abierto: %s", p.ID, r.Name), r.Sev, r.Why, r.Fix
					}
					e.find(f)
				}
			}
		}
	} else {
		e.find(model.Finding{
			Title: "Escaneo UDP omitido (requiere root)", Severity: model.Info,
			Detail:      "Los escaneos UDP con nmap necesitan privilegios.",
			Remediation: "Ejecuta `sudo sentinel …` desde fuera de tu LAN para cubrir los 50 puertos UDP más comunes (DNS, NTP, SNMP, SSDP…).",
		})
	}
}

func nmapReport(s *Scan, e emitter, run *nmapRun) {
	for _, h := range run.Hosts {
		for _, p := range h.Ports {
			if p.Proto != "tcp" {
				continue
			}
			s.updateVersion(p.ID, p.Service.Name, p.Service.Product, p.Service.Version)
			ver := strings.TrimSpace(p.Service.Product + " " + p.Service.Version)
			if ver != "" {
				e.find(model.Finding{
					Title: fmt.Sprintf("Servicio identificado en %d/tcp: %s", p.ID, ver), Severity: model.Info, Port: p.ID,
					Remediation: "Mantén este software actualizado; considera ocultar el banner de versión.",
				})
			}
			for _, sc := range p.Scripts {
				switch sc.ID {
				case "ssh-auth-methods":
					if strings.Contains(sc.Output, "password") || strings.Contains(sc.Output, "keyboard-interactive") {
						e.find(model.Finding{
							Title: fmt.Sprintf("SSH acepta autenticación por contraseña en %d/tcp", p.ID), Severity: model.High, Port: p.ID,
							Detail:      "Cualquiera en internet puede intentar fuerza bruta/credential stuffing contra tus usuarios.",
							Evidence:    strings.TrimSpace(sc.Output),
							Remediation: "En `/etc/ssh/sshd_config`: `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitRootLogin no`; `sshd -t && systemctl reload sshd`. Copia antes tu clave con `ssh-copy-id`. Complementa con fail2ban/CrowdSec.",
						})
					}
				case "vulners":
					var cves []string
					worst := 0.0
					for _, m := range vulnersRe.FindAllStringSubmatch(sc.Output, 12) {
						cves = append(cves, m[1]+" (CVSS "+m[2]+")")
						if v, _ := strconv.ParseFloat(m[2], 64); v > worst {
							worst = v
						}
					}
					if len(cves) == 0 {
						continue
					}
					sev := model.Medium
					switch {
					case worst >= 9:
						sev = model.Critical
					case worst >= 7:
						sev = model.High
					}
					e.find(model.Finding{
						Title: fmt.Sprintf("Posibles CVE en %s (%d/tcp)", ver, p.ID), Severity: sev, Port: p.ID,
						Detail:      "nmap/vulners asocia estas CVE a la versión detectada. Pueden ser falsos positivos si tu distribución parchea sin cambiar la versión.",
						Evidence:    strings.Join(cves, "\n"),
						Remediation: "Actualiza el paquete/imagen (`apt upgrade`, `docker pull` + recrear contenedor) y comprueba el changelog de la distro para confirmar si el parche está backportado.",
					})
				}
			}
		}
	}
}

// ---------- nuclei ----------

type nucleiLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Remediation string   `json:"remediation"`
		Reference   []string `json:"reference"`
	} `json:"info"`
	MatchedAt string   `json:"matched-at"`
	Extracted []string `json:"extracted-results"`
}

func webURLs(s *Scan) []string {
	var urls []string
	for _, p := range s.HTTPPorts() {
		sch := "http"
		if p.TLS {
			sch = "https"
		}
		urls = append(urls, fmt.Sprintf("%s://%s:%d", sch, s.T.Host, p.Port))
	}
	return urls
}

func checkNuclei(ctx context.Context, s *Scan, e emitter) {
	urls := webURLs(s)
	if len(urls) == 0 {
		e.status("sin servicios web")
		return
	}
	args := []string{"-severity", "medium,high,critical", "-jsonl", "-silent", "-nc", "-disable-update-check"}
	for _, u := range urls {
		args = append(args, "-u", u)
	}
	e.status("nuclei sobre %d URLs (puede tardar)…", len(urls))
	cctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "nuclei", args...)
	out, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		e.status("no se pudo ejecutar nuclei")
		return
	}
	n := 0
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var l nucleiLine
		if json.Unmarshal(sc.Bytes(), &l) != nil || l.TemplateID == "" {
			continue
		}
		n++
		f := model.Finding{
			Title: l.Info.Name, Severity: model.ParseSeverity(l.Info.Severity),
			Detail:      l.Info.Description,
			Evidence:    "template: " + l.TemplateID + "\nurl: " + l.MatchedAt + strings.Join(append([]string{""}, l.Extracted...), "\n"),
			Remediation: l.Info.Remediation,
			Refs:        l.Info.Reference,
		}
		if f.Remediation == "" {
			f.Remediation = "Consulta las referencias del template " + l.TemplateID + " y actualiza o reconfigura el servicio afectado; si no es necesario que sea público, restringe el acceso."
		}
		e.find(f)
	}
	cmd.Wait()
	e.status("%d hallazgos de nuclei", n)
}

// ---------- testssl.sh ----------

type testsslItem struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve"`
	Port     string `json:"port"`
}

func checkTestSSL(ctx context.Context, s *Scan, e emitter) {
	ports := s.TLSPorts()
	if len(ports) == 0 {
		e.status("sin puertos TLS")
		return
	}
	bin := "testssl.sh"
	if !have(bin) {
		bin = "testssl"
	}
	if len(ports) > 3 {
		ports = ports[:3]
	}
	for _, pi := range ports {
		e.status("testssl.sh en %d/tcp (puede tardar)…", pi.Port)
		tmp, err := os.CreateTemp("", "testssl-*.json")
		if err != nil {
			return
		}
		tmp.Close()
		os.Remove(tmp.Name()) // testssl refuses to overwrite
		cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
		target := fmt.Sprintf("%s:%d", s.T.Host, pi.Port)
		exec.CommandContext(cctx, bin, "--quiet", "--warnings", "off", "--color", "0", "--severity", "MEDIUM", "--jsonfile", tmp.Name(), target).Run()
		cancel()
		data, _ := os.ReadFile(tmp.Name())
		os.Remove(tmp.Name())
		var items []testsslItem
		if json.Unmarshal(data, &items) != nil {
			continue
		}
		for _, it := range items {
			var sev model.Severity
			switch strings.ToUpper(it.Severity) {
			case "LOW":
				sev = model.Low
			case "MEDIUM", "WARN":
				sev = model.Medium
			case "HIGH":
				sev = model.High
			case "CRITICAL":
				sev = model.Critical
			default:
				continue
			}
			e.find(model.Finding{
				Title: fmt.Sprintf("testssl: %s (%d/tcp)", it.ID, pi.Port), Severity: sev, Port: pi.Port,
				Detail:      it.Finding,
				Evidence:    it.CVE,
				Remediation: "Deshabilita el protocolo/suite afectado y adopta el perfil «Intermediate» de Mozilla: https://ssl-config.mozilla.org/ (nginx: `ssl_protocols TLSv1.2 TLSv1.3;` + lista de cifrados recomendada). Actualiza OpenSSL y el servidor web.",
				Refs:        []string{"https://ssl-config.mozilla.org/"},
			})
		}
	}
}
