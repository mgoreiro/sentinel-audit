package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"sentinel/internal/model"
	"sentinel/internal/report"
	"sentinel/internal/scan"
)

type stage int

const (
	stInput stage = iota
	stScan
	stResults
)

type Config struct {
	Target  string
	Full    bool
	Passive bool
	Local   bool
}

type row struct {
	name   string
	status string
	done   bool
}

type startedMsg struct {
	t      scan.Target
	ch     <-chan scan.Event
	cancel context.CancelFunc
}
type startErrMsg struct{ err error }
type evMsg scan.Event
type doneMsg struct{}

var (
	titleSt = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	dimSt   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	errSt   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	okSt    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	selSt   = lipgloss.NewStyle().Reverse(true)
)

func sevStyle(s model.Severity) lipgloss.Style {
	c := map[model.Severity]string{model.Critical: "196", model.High: "208", model.Medium: "220", model.Low: "39", model.Info: "244"}[s]
	return lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Bold(s >= model.High)
}

type Model struct {
	stage   stage
	input   textinput.Model
	focus   int
	full    bool
	passive bool
	local   bool
	owner   bool
	msg     string

	spin   spinner.Model
	rows   []*row
	byName map[string]*row
	ch     <-chan scan.Event
	cancel context.CancelFunc
	target scan.Target
	began  time.Time

	findings []model.Finding
	cursor   int
	filter   model.Severity
	vp       viewport.Model
	w, h     int
	exported string
}

func Run(cfg Config) error {
	_, err := tea.NewProgram(New(cfg), tea.WithAltScreen()).Run()
	return err
}

func New(cfg Config) *Model {
	ti := textinput.New()
	ti.Placeholder = "https://midominio.com · 203.0.113.7 · host:puerto"
	ti.SetValue(cfg.Target)
	ti.Focus()
	ti.Width = 60
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return &Model{input: ti, spin: sp, full: cfg.Full, passive: cfg.Passive, local: cfg.Local, byName: map[string]*row{}, w: 100, h: 30}
}

func (m *Model) Init() tea.Cmd { return textinput.Blink }

func (m *Model) startCmd() tea.Cmd {
	raw, opts := m.input.Value(), scan.Options{Full: m.full, Passive: m.passive, Local: m.local}
	return func() tea.Msg {
		t, err := scan.ParseTarget(raw)
		if err != nil {
			return startErrMsg{err}
		}
		ctx, cancel := context.WithCancel(context.Background())
		return startedMsg{t, scan.Start(ctx, t, opts), cancel}
	}
}

func waitEv(ch <-chan scan.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return doneMsg{}
		}
		return evMsg(ev)
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.layout()
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case startErrMsg:
		m.stage, m.msg = stInput, msg.err.Error()
		return m, nil

	case startedMsg:
		m.stage, m.target, m.ch, m.cancel, m.began = stScan, msg.t, msg.ch, msg.cancel, time.Now()
		m.rows, m.byName, m.findings = nil, map[string]*row{}, nil
		for _, n := range scan.Plan(scan.Options{Full: m.full, Passive: m.passive, Local: m.local}) {
			r := &row{name: n, status: "en cola"}
			m.rows = append(m.rows, r)
			m.byName[n] = r
		}
		return m, tea.Batch(m.spin.Tick, waitEv(m.ch))

	case evMsg:
		ev := scan.Event(msg)
		if r := m.byName[ev.Check]; r != nil {
			switch ev.Kind {
			case scan.EvStatus:
				r.status = ev.Msg
			case scan.EvDone:
				r.done = true
			}
		}
		if ev.Kind == scan.EvFinding {
			m.findings = append(m.findings, ev.Finding)
		}
		return m, waitEv(m.ch)

	case doneMsg:
		if m.cancel != nil {
			m.cancel()
		}
		model.Sort(m.findings)
		m.stage, m.cursor, m.filter = stResults, 0, model.Info
		m.layout()
		m.refreshDetail()
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
		switch m.stage {
		case stInput:
			return m.updateInput(msg)
		case stScan:
			if msg.String() == "esc" && m.cancel != nil {
				m.cancel() // engine closes the channel → doneMsg with partial results
			}
		case stResults:
			return m.updateResults(msg)
		}
	}
	return m, nil
}

func (m *Model) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	const fields = 5
	switch msg.String() {
	case "tab", "down":
		m.setFocus((m.focus + 1) % fields)
		return m, nil
	case "shift+tab", "up":
		m.setFocus((m.focus + fields - 1) % fields)
		return m, nil
	case "esc":
		return m, tea.Quit
	case "ctrl+s":
		return m.submit()
	case " ", "x":
		if m.focus >= 1 && m.focus <= 3 {
			m.toggle()
			return m, nil
		}
	case "enter":
		switch {
		case m.focus == 0:
			m.setFocus(1)
		case m.focus <= 3:
			m.toggle()
		default:
			return m.submit()
		}
		return m, nil
	}
	if m.focus == 0 {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) setFocus(i int) {
	m.focus = i
	if i == 0 {
		m.input.Focus()
	} else {
		m.input.Blur()
	}
}

func (m *Model) toggle() {
	switch m.focus {
	case 1:
		m.full = !m.full
	case 2:
		m.passive = !m.passive
	case 3:
		m.owner = !m.owner
	}
}

func (m *Model) submit() (tea.Model, tea.Cmd) {
	switch {
	case strings.TrimSpace(m.input.Value()) == "":
		m.msg = "Introduce una URL, dominio o IP."
	case !m.owner:
		m.msg = "Confirma que el destino es tuyo o que tienes autorización escrita para auditarlo."
	default:
		m.msg = "Resolviendo…"
		return m, m.startCmd()
	}
	return m, nil
}

func (m *Model) visible() []model.Finding {
	var out []model.Finding
	for _, f := range m.findings {
		if f.Severity >= m.filter {
			out = append(out, f)
		}
	}
	return out
}

func (m *Model) updateResults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	vis := m.visible()
	switch msg.String() {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(vis)-1 {
			m.cursor++
		}
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = max(0, len(vis)-1)
	case "f":
		m.filter = (m.filter + 1) % 5
		m.cursor = 0
	case "pgdown", "ctrl+d":
		m.vp.HalfViewDown()
		return m, nil
	case "pgup", "ctrl+u":
		m.vp.HalfViewUp()
		return m, nil
	case "e":
		m.exported = m.export()
	case "r":
		*m = *New(Config{Target: m.input.Value(), Full: m.full, Passive: m.passive, Local: m.local})
		return m, textinput.Blink
	}
	m.refreshDetail()
	return m, nil
}

func (m *Model) export() string {
	stamp := time.Now().Format("20060102-150405")
	base := fmt.Sprintf("sentinel-%s-%s", strings.NewReplacer(":", "_", "/", "_").Replace(m.target.Host), stamp)
	md := report.Markdown(m.target.Input, time.Now(), m.findings)
	js, _ := report.JSON(m.target.Input, time.Now(), m.findings)
	if err := os.WriteFile(base+".md", []byte(md), 0o600); err != nil {
		return "error: " + err.Error()
	}
	os.WriteFile(base+".json", js, 0o600)
	return "guardado " + base + ".md / .json"
}

func (m *Model) layout() {
	dw := m.w - m.w*42/100 - 3
	m.vp = viewport.New(max(20, dw), max(5, m.h-6))
}

func (m *Model) refreshDetail() {
	vis := m.visible()
	if len(vis) == 0 {
		m.vp.SetContent(dimSt.Render("Sin hallazgos con este filtro."))
		return
	}
	m.cursor = min(m.cursor, len(vis)-1)
	m.vp.SetContent(detail(vis[m.cursor], m.vp.Width))
	m.vp.GotoTop()
}

func detail(f model.Finding, w int) string {
	wrap := lipgloss.NewStyle().Width(w)
	var b strings.Builder
	b.WriteString(sevStyle(f.Severity).Render("["+f.Severity.String()+"] ") + titleSt.Render(f.Title) + "\n")
	meta := "check: " + f.Check
	if f.Port != 0 {
		meta += fmt.Sprintf(" · puerto %d", f.Port)
	}
	b.WriteString(dimSt.Render(meta) + "\n\n")
	if f.Detail != "" {
		b.WriteString(wrap.Render(f.Detail) + "\n\n")
	}
	if f.Evidence != "" {
		b.WriteString(titleSt.Render("Evidencia") + "\n" + wrap.Foreground(lipgloss.Color("245")).Render(f.Evidence) + "\n\n")
	}
	if f.Remediation != "" {
		b.WriteString(okSt.Bold(true).Render("Solución") + "\n" + wrap.Render(f.Remediation) + "\n\n")
	}
	for _, r := range f.Refs {
		b.WriteString(dimSt.Render(wrap.Render("→ "+r)) + "\n")
	}
	return b.String()
}

func (m *Model) View() string {
	switch m.stage {
	case stInput:
		return m.viewInput()
	case stScan:
		return m.viewScan()
	}
	return m.viewResults()
}

func box(on bool, focused bool, label string) string {
	mark := "[ ]"
	if on {
		mark = "[x]"
	}
	s := mark + " " + label
	if focused {
		return selSt.Render(s)
	}
	return s
}

func (m *Model) viewInput() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("SENTINEL") + dimSt.Render(" · auditoría de superficie expuesta") + "\n\n")
	b.WriteString("Destino (URL, dominio o IP)\n" + m.input.View() + "\n\n")
	b.WriteString(box(m.full, m.focus == 1, "Escaneo completo de los 65535 puertos TCP (más lento)") + "\n")
	b.WriteString(box(m.passive, m.focus == 2, "Fuentes pasivas: crt.sh y Shodan (envían el dominio/IP a terceros)") + "\n")
	b.WriteString(box(m.owner, m.focus == 3, "Confirmo que el destino es mío o tengo autorización para auditarlo") + "\n\n")
	btn := "[ Iniciar auditoría ]"
	if m.focus == 4 {
		btn = selSt.Render(btn)
	}
	b.WriteString(btn + "\n\n")
	if m.msg != "" {
		b.WriteString(errSt.Render(m.msg) + "\n\n")
	}
	b.WriteString(dimSt.Render("tab: mover · espacio: marcar · enter: aceptar · ctrl+s: iniciar · esc: salir") + "\n\n")
	var tools []string
	for _, n := range scan.Plan(scan.Options{Passive: m.passive, Local: m.local}) {
		tools = append(tools, n)
	}
	b.WriteString(dimSt.Render("Checks activos: " + strings.Join(tools, ", ")))
	b.WriteString(dimSt.Render("\nConsejo: ejecútalo desde fuera de tu LAN (4G o VPS) para ver lo que ve un atacante."))
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m *Model) viewScan() string {
	var b strings.Builder
	c := model.Counts(m.findings)
	b.WriteString(titleSt.Render("Auditando ") + m.target.Host + dimSt.Render(fmt.Sprintf(" (%s) · %s", m.target.Addr, time.Since(m.began).Round(time.Second))) + "\n\n")
	for _, r := range m.rows {
		icon := m.spin.View()
		if r.done {
			icon = okSt.Render("✓")
		}
		st := r.status
		if lipgloss.Width(st) > m.w-30 {
			st = st[:max(0, m.w-33)] + "…"
		}
		fmt.Fprintf(&b, "%s %-20s %s\n", icon, r.name, dimSt.Render(st))
	}
	fmt.Fprintf(&b, "\nHallazgos: %s %s %s %s %s\n",
		sevStyle(model.Critical).Render(fmt.Sprintf("%d crít", c[model.Critical])),
		sevStyle(model.High).Render(fmt.Sprintf("%d alto", c[model.High])),
		sevStyle(model.Medium).Render(fmt.Sprintf("%d medio", c[model.Medium])),
		sevStyle(model.Low).Render(fmt.Sprintf("%d bajo", c[model.Low])),
		sevStyle(model.Info).Render(fmt.Sprintf("%d info", c[model.Info])))
	b.WriteString(dimSt.Render("\nesc: terminar y ver resultados parciales · ctrl+c: salir"))
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m *Model) viewResults() string {
	vis := m.visible()
	c := model.Counts(m.findings)
	head := titleSt.Render(m.target.Host) + "  " +
		sevStyle(model.Critical).Render(fmt.Sprintf("%d crít", c[model.Critical])) + " " +
		sevStyle(model.High).Render(fmt.Sprintf("%d alto", c[model.High])) + " " +
		sevStyle(model.Medium).Render(fmt.Sprintf("%d medio", c[model.Medium])) + " " +
		sevStyle(model.Low).Render(fmt.Sprintf("%d bajo", c[model.Low])) + " " +
		sevStyle(model.Info).Render(fmt.Sprintf("%d info", c[model.Info])) +
		dimSt.Render("  filtro ≥ "+m.filter.String())

	lw := m.w * 42 / 100
	rows := max(3, m.h-6)
	start := max(0, min(m.cursor-rows/2, len(vis)-rows))
	var lb strings.Builder
	for i := start; i < len(vis) && i < start+rows; i++ {
		f := vis[i]
		line := fmt.Sprintf("%-8s %s", f.Severity, f.Title)
		line = lipgloss.NewStyle().MaxWidth(lw - 2).Render(line)
		if i == m.cursor {
			lb.WriteString(selSt.Render(line))
		} else {
			lb.WriteString(sevStyle(f.Severity).Render(line))
		}
		lb.WriteString("\n")
	}
	left := lipgloss.NewStyle().Width(lw).Height(rows).Render(lb.String())
	right := lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).BorderForeground(lipgloss.Color("240")).PaddingLeft(1).Render(m.vp.View())

	foot := "↑↓ mover · pgup/pgdn leer · f filtro · e exportar · r nueva · q salir"
	if m.exported != "" {
		foot = okSt.Render(m.exported) + dimSt.Render(" · "+foot)
	} else {
		foot = dimSt.Render(foot)
	}
	return lipgloss.NewStyle().Padding(0, 1).Render(head + "\n\n" + lipgloss.JoinHorizontal(lipgloss.Top, left, right) + "\n" + foot)
}
