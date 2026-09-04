package tui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/JorgeCarvalhoPT/nullbox/internal/engage"
	nbmodel "github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

// UI modes.
const (
	modeList = iota
	modeForm
	modeConfirm
)

type formField struct {
	label       string
	value       string
	placeholder string
	required    bool
}

type formState struct {
	fields    []formField
	focus     int
	err       string
	savedPath string
	built     *nbmodel.Engagement
}

// newForm returns a blank engagement form (window prefilled to +14 days).
func newForm() formState {
	end := time.Now().Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339)
	return formState{fields: []formField{
		{label: "name", required: true, placeholder: "acme-internal"},
		{label: "client", placeholder: "ACME Corp"},
		{label: "auth ref", required: true, placeholder: "SOW-2026-0142"},
		{label: "profile", required: true, value: "nat", placeholder: "nat | routed | l2"},
		{label: "driver", placeholder: "(auto) | krun | firecracker | clh | kata"},
		{label: "image", placeholder: "(default) any agent OCI image, e.g. ghcr.io/acme/agent:v1"},
		{label: "window end", value: end, placeholder: "RFC3339"},
		{label: "allow", required: true, placeholder: "10.10.0.0/16 10.20.5.0/24:443,8443 host.example.com"},
		{label: "deny", placeholder: "10.10.9.0/24"},
	}}
}

func (f formState) get(label string) string {
	for _, fd := range f.fields {
		if fd.label == label {
			return strings.TrimSpace(fd.value)
		}
	}
	return ""
}

// build assembles and validates an Engagement from the form.
func (f formState) build() (*nbmodel.Engagement, error) {
	allow, err := engage.ParseTargets(f.get("allow"))
	if err != nil {
		return nil, err
	}
	deny, err := engage.ParseTargets(f.get("deny"))
	if err != nil {
		return nil, err
	}
	e := &nbmodel.Engagement{
		APIVersion: "nullbox/v1", Kind: "Engagement",
		Metadata: nbmodel.Metadata{
			Name:          f.get("name"),
			Client:        f.get("client"),
			Authorization: nbmodel.Authorization{Ref: f.get("auth ref")},
		},
		Spec: nbmodel.Spec{
			Driver:  nbmodel.Driver(f.get("driver")),
			Image:   f.get("image"),
			Window:  nbmodel.Window{End: f.get("window end")},
			Network: nbmodel.Network{Profile: nbmodel.Profile(f.get("profile"))},
			Scope:   nbmodel.Scope{Allow: allow, Deny: deny},
		},
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// updateForm handles keys while the new-engagement form is open.
func (m model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeList
		m.form = formState{}
		return m, nil
	case "tab", "down":
		m.form.focus = (m.form.focus + 1) % len(m.form.fields)
	case "shift+tab", "up":
		m.form.focus = (m.form.focus - 1 + len(m.form.fields)) % len(m.form.fields)
	case "enter":
		return m.submitForm()
	case "backspace":
		f := &m.form.fields[m.form.focus]
		if r := []rune(f.value); len(r) > 0 {
			f.value = string(r[:len(r)-1])
		}
	default:
		switch msg.Type {
		case tea.KeyRunes:
			m.form.fields[m.form.focus].value += string(msg.Runes)
		case tea.KeySpace:
			m.form.fields[m.form.focus].value += " "
		}
	}
	return m, nil
}

// submitForm validates, writes a manifest, and moves to the boot? confirm.
func (m model) submitForm() (tea.Model, tea.Cmd) {
	e, err := m.form.build()
	if err != nil {
		m.form.err = err.Error()
		return m, nil
	}
	path, err := engage.WriteManifest(e, "")
	if err != nil {
		m.form.err = err.Error()
		return m, nil
	}
	m.form.savedPath = path
	m.form.built = e
	m.mode = modeConfirm
	return m, nil
}

type bootDoneMsg struct {
	name string
	err  error
}

// updateConfirm handles the "boot now?" prompt.
func (m model) updateConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		e := m.form.built
		path := m.form.savedPath
		m.mode = modeList
		m.form = formState{}
		m.status = e.Metadata.Name + ": booting…"
		return m, func() tea.Msg {
			_, _, err := engage.Up(e, e.Spec.Workspace, path)
			return bootDoneMsg{name: e.Metadata.Name, err: err}
		}
	case "n", "N", "esc":
		saved := m.form.savedPath
		m.mode = modeList
		m.form = formState{}
		m.status = "saved " + saved + " (not booted — run `nullbox up` when ready)"
		return m, nil
	}
	return m, nil
}

// --- views ---

func (m model) formView() string {
	st := m.st
	ink, muted, faint := st.fg(st.ink), st.fg(st.muted), st.fg(st.faint)
	var b strings.Builder
	b.WriteString(ink.Bold(true).Render("New engagement") + "\n")
	b.WriteString(muted.Render("scope + window + auth are per-engagement; the rest is your call") + "\n\n")
	for i, f := range m.form.fields {
		label := f.label
		if f.required {
			label += " *"
		}
		lbl := faint.Render(pad(label, 12))
		val := f.value
		style := lipgloss.NewStyle()
		if i == m.form.focus {
			lbl = st.fg(st.blue).Bold(true).Render(pad("▸ "+label, 12))
			style = st.fg(st.ink)
		} else {
			style = st.fg(st.ink)
		}
		shown := style.Render(val)
		if val == "" {
			shown = faint.Render(f.placeholder)
		}
		if i == m.form.focus {
			shown += st.fg(st.blue).Render("▏")
		}
		b.WriteString(lbl + "  " + shown + "\n")
	}
	b.WriteString("\n")
	if m.form.err != "" {
		b.WriteString(st.fg(st.red).Render("✗ "+m.form.err) + "\n\n")
	}
	key := func(k, d string) string { return ink.Bold(true).Render(k) + " " + muted.Render(d) }
	b.WriteString(strings.Join([]string{key("↑↓/tab", "field"), key("⏎", "save"), key("esc", "cancel")}, "   "))
	return m.chrome(b.String())
}

func (m model) confirmView() string {
	st := m.st
	ink, muted, green := st.fg(st.ink), st.fg(st.muted), st.fg(st.green)
	var b strings.Builder
	b.WriteString(green.Render("✓ saved ") + ink.Render(m.form.savedPath) + "\n\n")
	b.WriteString(ink.Bold(true).Render("Boot it now?") + "\n\n")
	key := func(k, d string) string { return ink.Bold(true).Render(k) + " " + muted.Render(d) }
	b.WriteString(strings.Join([]string{key("y", "boot the sandbox"), key("n", "keep the manifest, don't boot")}, "   "))
	return m.chrome(b.String())
}

// chrome wraps form/confirm content in the same window frame as the list view.
func (m model) chrome(body string) string {
	st := m.st
	w := m.w
	if w < 92 {
		w = 92
	}
	dots := st.fg(st.red).Render("●") + " " + st.fg(st.yellow).Render("●") + " " + st.fg(st.green).Render("●")
	title := st.fg(st.muted).Render("nullbox — pentest sandboxes")
	titleBar := lipgloss.JoinHorizontal(lipgloss.Top, "  "+dots+"  ",
		lipgloss.PlaceHorizontal(clampw(w-lipgloss.Width(dots)-6), lipgloss.Center, title))
	rule := st.fg(st.faint).Render(strings.Repeat("─", w))
	return lipgloss.JoinVertical(lipgloss.Left, "", titleBar, rule, "", "  "+strings.ReplaceAll(body, "\n", "\n  "))
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
