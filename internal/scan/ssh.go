package scan

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	"sentinel/internal/model"
)

var opensshRe = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)

func checkSSH(ctx context.Context, s *Scan, e emitter) {
	found := false
	for _, pi := range s.Ports() {
		if pi.Service != "ssh" {
			continue
		}
		found = true
		m := opensshRe.FindStringSubmatch(pi.Banner)
		if m == nil {
			e.status("SSH en %d/tcp: %s", pi.Port, pi.Banner)
			continue
		}
		maj, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		ver := maj*100 + min
		switch {
		case ver >= 805 && ver < 908:
			e.find(model.Finding{
				Title: fmt.Sprintf("OpenSSH %d.%d potencialmente vulnerable a regreSSHion (CVE-2024-6387)", maj, min), Severity: model.High, Port: pi.Port,
				Detail:      "Las versiones 8.5p1–9.7p1 tienen una condición de carrera en sshd que puede dar RCE como root. Las distros suelen aplicar backports sin cambiar el número, así que verifica con el gestor de paquetes.",
				Evidence:    pi.Banner,
				Remediation: "Actualiza openssh-server (`apt update && apt upgrade openssh-server`) a una versión con el parche, o define `LoginGraceTime 0` como mitigación temporal.",
				Refs:        []string{"https://www.qualys.com/regresshion-cve-2024-6387/"},
			})
		case ver < 805:
			e.find(model.Finding{
				Title: fmt.Sprintf("OpenSSH %d.%d obsoleto", maj, min), Severity: model.Medium, Port: pi.Port,
				Detail:      "Versión antigua con vulnerabilidades conocidas y algoritmos débiles habilitados.",
				Evidence:    pi.Banner,
				Remediation: "Actualiza el sistema operativo/paquete openssh-server a una versión soportada.",
			})
		}
	}
	if !found {
		e.status("sin servicio SSH detectado")
	}
}
