package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"sentinel/internal/model"
)

var dynDNSSuffixes = []string{"mooo.com", "afraid.org", "duckdns.org", "ddns.net", "no-ip.com", "no-ip.org", "hopto.org", "dynu.net", "myftp.biz", "zapto.org"}

func checkPassive(ctx context.Context, s *Scan, e emitter) {
	if !s.T.IsIP {
		e.status("consultando Certificate Transparency (crt.sh)…")
		crtSh(ctx, s, e)
		dynDNSNotes(s, e)
	}
	if key := os.Getenv("SHODAN_API_KEY"); key != "" {
		e.status("consultando Shodan…")
		shodan(ctx, s, e, key)
	} else {
		e.status("Shodan omitido (define SHODAN_API_KEY para activarlo)")
	}
}

func crtSh(ctx context.Context, s *Scan, e emitter) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://crt.sh/?output=json&q="+url.QueryEscape("%."+s.T.Host), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		e.status("crt.sh no disponible")
		return
	}
	defer resp.Body.Close()
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if json.NewDecoder(resp.Body).Decode(&rows) != nil {
		e.status("respuesta de crt.sh no válida")
		return
	}
	set := map[string]bool{}
	for _, r := range rows {
		for _, n := range strings.Split(r.NameValue, "\n") {
			set[strings.ToLower(strings.TrimSpace(n))] = true
		}
	}
	if len(set) == 0 {
		e.status("crt.sh: sin certificados públicos")
		return
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	shown := names
	if len(shown) > 40 {
		shown = shown[:40]
	}
	e.find(model.Finding{
		Title: fmt.Sprintf("%d nombres públicos en Certificate Transparency", len(names)), Severity: model.Info,
		Detail:      "Cualquier atacante puede listar estos subdominios sin tocar tu servidor; cada uno es superficie de ataque adicional.",
		Evidence:    strings.Join(shown, "\n"),
		Remediation: "Revisa que cada nombre siga en uso y protegido. Evita subdominios que revelen servicios internos (`admin.`, `vpn.`, `pihole.`): usa un certificado wildcard (DNS-01) para no publicar nombres, o rutas bajo un único host.",
		Refs:        []string{"https://crt.sh/?q=" + url.QueryEscape(s.T.Host)},
	})
}

func dynDNSNotes(s *Scan, e emitter) {
	for _, suf := range dynDNSSuffixes {
		if s.T.Host == suf || strings.HasSuffix(s.T.Host, "."+suf) {
			e.find(model.Finding{
				Title: "Dominio de DNS dinámico gratuito (" + suf + ")", Severity: model.Low,
				Detail:      "Quien controle tu cuenta del proveedor DNS dinámico puede redirigir el dominio a su servidor y capturar tráfico o emitir certificados.",
				Remediation: "Activa 2FA y una contraseña única en la cuenta del proveedor (FreeDNS/DuckDNS/No-IP), revisa los registros periódicamente y valora un dominio propio con registrador que ofrezca 2FA y registry lock.",
			})
			return
		}
	}
}

func shodan(ctx context.Context, s *Scan, e emitter, key string) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.shodan.io/shodan/host/"+s.T.Addr.String()+"?key="+url.QueryEscape(key), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.status("Shodan no disponible")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		e.status("Shodan no tiene esta IP indexada")
		return
	}
	if resp.StatusCode != 200 {
		e.status("Shodan respondió %d", resp.StatusCode)
		return
	}
	var h struct {
		Ports []int    `json:"ports"`
		Vulns []string `json:"vulns"`
	}
	if json.NewDecoder(resp.Body).Decode(&h) != nil {
		return
	}
	var ports []string
	for _, p := range h.Ports {
		ports = append(ports, fmt.Sprint(p))
	}
	e.find(model.Finding{
		Title: "Shodan indexa " + fmt.Sprint(len(h.Ports)) + " puertos de esta IP", Severity: model.Info,
		Evidence:    strings.Join(ports, ", "),
		Detail:      "Es lo que ve un atacante sin escanearte. Compáralo con los puertos abiertos de esta auditoría: los que ya no responden pueden ser datos antiguos o servicios intermitentes.",
		Remediation: "Cierra los puertos que no deban ser públicos; Shodan los reindexará en días.",
		Refs:        []string{"https://www.shodan.io/host/" + s.T.Addr.String()},
	})
	if len(h.Vulns) > 0 {
		e.find(model.Finding{
			Title: fmt.Sprintf("Shodan asocia %d CVE a esta IP", len(h.Vulns)), Severity: model.High,
			Evidence: strings.Join(h.Vulns, ", "),
			Detail:   "Shodan los infiere por banners de versión; pueden ser falsos positivos si la distro aplica backports.",
		})
	}
}
