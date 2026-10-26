package model

import (
	"encoding/json"
	"sort"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "UNKNOWN"
	}
	return severityNames[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func ParseSeverity(v string) Severity {
	v = strings.ToUpper(strings.TrimSpace(v))
	for i, n := range severityNames {
		if n == v {
			return Severity(i)
		}
	}
	return Info
}

// Finding is a single issue plus the advice to fix it.
type Finding struct {
	Check       string   `json:"check"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Port        int      `json:"port,omitempty"`
	Detail      string   `json:"detail,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Refs        []string `json:"refs,omitempty"`
}

// Sort orders findings from most to least severe.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].Port != fs[j].Port {
			return fs[i].Port < fs[j].Port
		}
		return fs[i].Title < fs[j].Title
	})
}

func Counts(fs []Finding) [5]int {
	var c [5]int
	for _, f := range fs {
		c[f.Severity]++
	}
	return c
}
