package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"sentinel/internal/model"
)

func Markdown(target string, when time.Time, fs []model.Finding) string {
	var b strings.Builder
	c := model.Counts(fs)
	fmt.Fprintf(&b, "# Auditoría de seguridad: %s\n\n_%s_\n\n", target, when.Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, "| Crítico | Alto | Medio | Bajo | Info |\n|---|---|---|---|---|\n| %d | %d | %d | %d | %d |\n\n", c[model.Critical], c[model.High], c[model.Medium], c[model.Low], c[model.Info])
	for _, f := range fs {
		fmt.Fprintf(&b, "## [%s] %s\n\n", f.Severity, f.Title)
		if f.Detail != "" {
			fmt.Fprintf(&b, "%s\n\n", f.Detail)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "**Evidencia**\n\n```\n%s\n```\n\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "**Solución**\n\n%s\n\n", f.Remediation)
		}
		for _, r := range f.Refs {
			fmt.Fprintf(&b, "- %s\n", r)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func JSON(target string, when time.Time, fs []model.Finding) ([]byte, error) {
	return json.MarshalIndent(struct {
		Target   string          `json:"target"`
		When     time.Time       `json:"when"`
		Findings []model.Finding `json:"findings"`
	}{target, when, fs}, "", "  ")
}
