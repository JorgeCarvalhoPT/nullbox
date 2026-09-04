package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/JorgeCarvalhoPT/nullbox/internal/buildinfo"
)

type styles struct {
	ink, muted, faint, green, red, purple, yellow, blue, border lipgloss.TerminalColor
	card, cardActive                                            lipgloss.Style
}

func (s styles) fg(c lipgloss.TerminalColor) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }

func newStyles() styles {
	ad := func(l, d string) lipgloss.AdaptiveColor { return lipgloss.AdaptiveColor{Light: l, Dark: d} }
	s := styles{
		ink:    ad("#343b58", "#c0caf5"),
		muted:  ad("#6a76a8", "#565f89"),
		faint:  ad("#8891ba", "#3b4261"),
		green:  ad("#587539", "#9ece6a"),
		red:    ad("#e2496b", "#f7768e"),
		purple: ad("#7847bd", "#bb9af7"),
		yellow: ad("#8f6c30", "#e0af68"),
		blue:   ad("#3760bf", "#7aa2f7"),
		border: ad("#b3b7cc", "#2d2f44"),
	}
	s.card = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(s.border).Padding(0, 1)
	s.cardActive = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(s.blue).Padding(0, 1)
	return s
}

func clampw(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
func cell(s string, w int) string { return lipgloss.NewStyle().Width(clampw(w)).Render(s) }

func (m model) View() string {
	if m.mode == modeForm {
		return m.formView()
	}
	if m.mode == modeConfirm {
		return m.confirmView()
	}
	st := m.st
	w := m.w
	if w < 92 {
		w = 92
	}
	ink, muted, faint, green := st.fg(st.ink), st.fg(st.muted), st.fg(st.faint), st.fg(st.green)

	dots := st.fg(st.red).Render("●") + " " + st.fg(st.yellow).Render("●") + " " + green.Render("●")
	title := muted.Render("nullbox — pentest sandboxes")
	titleBar := lipgloss.JoinHorizontal(lipgloss.Top, "  "+dots+"  ",
		lipgloss.PlaceHorizontal(clampw(w-lipgloss.Width(dots)-6), lipgloss.Center, title))

	brand := ink.Bold(true).Render("null") + green.Bold(true).Render("box")
	tagline := muted.Render("Run pentest agents in isolated microVMs — packet-scoped egress")
	conn := muted.Render("● demo")
	if !m.demo {
		conn = green.Render("● live")
	}
	appLeft := "  " + brand + "  " + tagline
	appbar := lipgloss.JoinHorizontal(lipgloss.Top, appLeft,
		lipgloss.PlaceHorizontal(clampw(w-lipgloss.Width(appLeft)), lipgloss.Right, conn+"  "))

	leftW := 36
	rightW := w - leftW - 4
	if rightW < 34 {
		rightW = 34
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, m.renderList(leftW), "  ", m.renderPane(rightW))

	key := func(k, label string) string { return ink.Bold(true).Render(k) + " " + muted.Render(label) }
	keys := strings.Join([]string{key("↑↓", "select"), key("n", "new"), key("x", "exec"), key("d", "stop"), key("k", "kill"), key("q", "quit")}, "   ")
	if m.status != "" {
		keys = key("↑↓", "select") + "   " + st.fg(st.yellow).Render(m.status)
	}
	ver := faint.Render(fmt.Sprintf("nullbox %s · %d running", buildinfo.Version, m.runningCount()))
	statusLeft := "  " + keys
	statusBar := lipgloss.JoinHorizontal(lipgloss.Top, statusLeft,
		lipgloss.PlaceHorizontal(clampw(w-lipgloss.Width(statusLeft)), lipgloss.Right, ver+"  "))

	rule := faint.Render(strings.Repeat("─", w))
	return lipgloss.JoinVertical(lipgloss.Left, "", titleBar, rule, appbar, rule, "", body, "", rule, statusBar)
}

func (m model) renderList(w int) string {
	var cards []string
	for i, e := range m.engs {
		cards = append(cards, m.renderCard(e, i == m.sel, w))
	}
	return lipgloss.JoinVertical(lipgloss.Left, cards...)
}

func (m model) renderCard(e engagement, active bool, w int) string {
	st := m.st
	ink, muted, faint := st.fg(st.ink), st.fg(st.muted), st.fg(st.faint)
	state := m.stateOf(e)
	glyph, gc := "■", st.red
	switch state {
	case "running":
		glyph, gc = "◔", st.green
	case "expired":
		glyph, gc = "▸", st.yellow
	}
	inner := w - 4
	nameLine := st.fg(gc).Render(glyph) + " " + ink.Bold(true).Render(e.name)
	tag := st.fg(st.purple).Bold(true).Render("microVM")
	head := lipgloss.JoinHorizontal(lipgloss.Top, nameLine,
		lipgloss.PlaceHorizontal(clampw(inner-lipgloss.Width(nameLine)), lipgloss.Right, tag))

	stat := muted.Render(state)
	if state == "running" {
		stat = muted.Render(truncate(e.res, inner))
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		head,
		muted.Render("AI pentest agent"),
		faint.Render(truncate(e.workspace, inner)),
		stat,
		"",
		m.renderActs(state),
	)
	style := st.card
	if active {
		style = st.cardActive
	}
	return style.Width(w - 2).Render(content)
}

func (m model) renderActs(state string) string {
	st := m.st
	if state != "running" {
		return st.fg(st.faint).Render("start  exec  remove")
	}
	act := func(word string, base lipgloss.TerminalColor) string {
		return st.fg(st.yellow).Render(word[:1]) + st.fg(base).Render(word[1:])
	}
	return act("stop", st.muted) + "  " + act("exec", st.ink) + "  " + act("kill", st.red)
}

func (m model) renderPane(w int) string {
	st := m.st
	ink, muted, faint := st.fg(st.ink), st.fg(st.muted), st.fg(st.faint)
	if len(m.engs) == 0 {
		return faint.Render("No engagements. Run `nullbox up <manifest>`.")
	}
	e := m.engs[m.sel]
	state := m.stateOf(e)
	rows := aggregate(e)

	title := ink.Bold(true).Render(e.name) + "   " + muted.Render(e.client)
	tabs := m.tabLabel("Egress Log", len(rows), m.tab == tabEgress) + "    " +
		m.tabLabel("Scope Rules", len(e.scope)+1, m.tab == tabScope)
	rule := faint.Render(strings.Repeat("─", w))

	banner := ""
	switch state {
	case "expired":
		banner = st.fg(st.yellow).Render("window elapsed — egress auto-expired; scope no longer authorized") + "\n\n"
	case "killed":
		banner = st.fg(st.red).Render("egress flushed — nft table deleted; nothing leaves this microVM") + "\n\n"
	}

	var content string
	if m.tab == tabEgress {
		content = m.egressView(e, rows, w)
	} else {
		content = m.scopeView(e, w)
	}
	return lipgloss.JoinVertical(lipgloss.Left, title, "", tabs, rule, "", banner+content)
}

func (m model) tabLabel(label string, count int, active bool) string {
	st := m.st
	cnt := st.fg(st.faint).Render(fmt.Sprintf("(%d)", count))
	name := st.fg(st.muted).Render(label)
	if active {
		name = st.fg(st.ink).Bold(true).Underline(true).Render(label)
	}
	return name + " " + cnt
}

func (m model) egressView(e engagement, rows []aggRow, w int) string {
	st := m.st
	muted, green, red := st.fg(st.muted), st.fg(st.green), st.fg(st.red)
	allowed, dropped := 0, 0
	for _, r := range rows {
		if r.verdict == "drop" {
			dropped++
		} else {
			allowed++
		}
	}
	summary := muted.Render(fmt.Sprintf("%d destinations", len(rows))) + "   " +
		green.Render(fmt.Sprintf("● %d allowed", allowed)) + "   " + red.Render(fmt.Sprintf("● %d dropped", dropped))
	if len(rows) == 0 {
		return summary + "\n\n" + st.fg(st.faint).Render("no egress yet — the agent hasn't reached the network")
	}

	// Row layout: "● "(2) + time(10) + dest(destW) + hits(6) + "  "(2) + status(7)
	timeW, hitsW, statusW := 10, 6, 7
	destW := w - 2 - timeW - hitsW - 2 - statusW
	if destW < 16 {
		destW = 16
	}
	rightHits := lipgloss.NewStyle().Width(hitsW).Align(lipgloss.Right)
	header := muted.Render("  " + cell("Last seen", timeW) + cell("Destination", destW) +
		rightHits.Render("Hits") + "  " + "Status")

	lines := []string{header}
	n := len(rows)
	if n > 13 {
		n = 13
	}
	for _, r := range rows[:n] {
		dc := st.green
		if r.verdict == "drop" {
			dc = st.red
		}
		dot := st.fg(dc).Render("●")
		t := cell(st.fg(st.faint).Render(r.ts.Format("15:04:05")), timeW)
		// budget the destination so the plain width never exceeds destW (else lipgloss wraps)
		tail := fmt.Sprintf(":%d %s", r.dport, r.proto)
		note := ""
		if r.note != "" {
			note = " ✕ " + r.note
		}
		host := truncate(r.dst, max(4, destW-len([]rune(tail))-len([]rune(note))))
		dst := st.fg(st.ink).Render(host) + muted.Render(tail) + red.Render(note)
		destCell := cell(dst, destW)
		hits := rightHits.Render(muted.Render(fmt.Sprintf("%d", r.hits)))
		status := green.Render("Allowed")
		if r.verdict == "drop" {
			status = red.Render("Dropped")
		}
		lines = append(lines, lipgloss.JoinHorizontal(lipgloss.Top, dot+" ", t, destCell, hits, "  ", status))
	}
	foot := green.Render(fmt.Sprintf("%d allowed", allowed)) + muted.Render(" · ") + red.Render(fmt.Sprintf("%d dropped", dropped))
	return lipgloss.JoinVertical(lipgloss.Left, summary, "", lipgloss.JoinVertical(lipgloss.Left, lines...), "", foot)
}

func (m model) scopeView(e engagement, w int) string {
	st := m.st
	muted := st.fg(st.muted)
	destW := w - 12 - 10
	if destW < 18 {
		destW = 18
	}
	header := muted.Render(cell("Destination", destW) + cell("Ports", 12) + "Action")
	lines := []string{header, ""}
	for _, s := range e.scope {
		host, ports := s.target, "all"
		if i := strings.IndexByte(s.target, ':'); i >= 0 {
			host, ports = s.target[:i], s.target[i+1:]
		}
		action := st.fg(st.green).Render("allow")
		if s.kind == "deny" {
			action = st.fg(st.red).Render("deny")
		}
		lines = append(lines, cell(st.fg(st.ink).Render(host), destW)+cell(muted.Render(ports), 12)+action)
	}
	// the always-on rule the compiler emits
	lines = append(lines, cell(st.fg(st.ink).Render("169.254.169.254")+st.fg(st.faint).Render(" metadata"), destW)+
		cell(muted.Render("all"), 12)+st.fg(st.red).Render("deny"))
	lines = append(lines, "", muted.Render("deny-by-default · deny wins · compiled to nftables"))
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}
