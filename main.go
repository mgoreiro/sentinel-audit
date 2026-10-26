package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"sentinel/internal/model"
	"sentinel/internal/report"
	"sentinel/internal/scan"
	"sentinel/internal/tui"
)

func main() {
	var (
		full      = flag.Bool("full", false, "escanear los 65535 puertos TCP")
		noPassive = flag.Bool("no-passive", false, "no consultar crt.sh/Shodan")
		local     = flag.Bool("local", false, "auditar también Docker en esta máquina")
		plain     = flag.Bool("plain", false, "modo sin TUI (requiere destino y --yes)")
		yes       = flag.Bool("yes", false, "confirmo que el destino es mío o tengo autorización")
		mdOut     = flag.String("md", "", "ruta del informe Markdown (modo --plain)")
		jsonOut   = flag.String("json", "", "ruta del informe JSON (modo --plain)")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "uso: sentinel [opciones] [url|dominio|ip]\n\nAudita la superficie expuesta de un servidor PROPIO (o autorizado).\nEjecútalo desde fuera de tu LAN para ver lo que ve un atacante.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	target := flag.Arg(0)

	if !*plain {
		if err := tui.Run(tui.Config{Target: target, Full: *full, Passive: !*noPassive, Local: *local}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if target == "" || !*yes {
		fmt.Fprintln(os.Stderr, "--plain requiere un destino y --yes (confirmación de que es tuyo o autorizado)")
		os.Exit(2)
	}
	t, err := scan.ParseTarget(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Fprintf(os.Stderr, "Auditando %s (%s)\n", t.Host, t.Addr)

	var fs []model.Finding
	for ev := range scan.Start(ctx, t, scan.Options{Full: *full, Passive: !*noPassive, Local: *local}) {
		switch ev.Kind {
		case scan.EvStatus:
			fmt.Fprintf(os.Stderr, "  [%s] %s\n", ev.Check, ev.Msg)
		case scan.EvFinding:
			fs = append(fs, ev.Finding)
		}
	}
	model.Sort(fs)
	now := time.Now()
	for _, f := range fs {
		fmt.Printf("%-8s %s\n", f.Severity, f.Title)
		if f.Remediation != "" && f.Severity >= model.Low {
			fmt.Printf("         ↳ %s\n", f.Remediation)
		}
	}
	if *mdOut != "" {
		os.WriteFile(*mdOut, []byte(report.Markdown(target, now, fs)), 0o600)
	}
	if *jsonOut != "" {
		if b, err := report.JSON(target, now, fs); err == nil {
			os.WriteFile(*jsonOut, b, 0o600)
		}
	}
	if c := model.Counts(fs); c[model.High]+c[model.Critical] > 0 {
		os.Exit(3)
	}
}
