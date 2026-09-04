// Package tui is nullbox's in-terminal interface — the sbx-equivalent, built on
// the same stack (charmbracelet/bubbletea + lipgloss). It lives in the terminal:
// `nullbox` with no arguments launches it. Left column lists engagements; the
// right pane shows the live egress log (allowed vs dropped) and the compiled
// scope rules; the bottom bar carries the key hints. It reads the engagement
// store, and falls back to demo data when the store is empty so the interface
// is populated on first run (marked "demo").
package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/JorgeCarvalhoPT/nullbox/internal/driver"
	nbmodel "github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/store"
)

// Run launches the TUI (full-screen, alternate buffer).
func Run() error {
	_, err := tea.NewProgram(New(), tea.WithAltScreen()).Run()
	return err
}

type tab int

const (
	tabEgress tab = iota
	tabScope
)

type scopeEntry struct{ target, kind string }

type flowEvent struct {
	ts      time.Time
	proto   string
	dst     string
	dport   int
	verdict string // "accept" | "drop"
	note    string
}

type engagement struct {
	name, client, driver, profile, state      string
	authRef, windowEnd, image, workspace, res string
	scope                                     []scopeEntry
	dsts, outs                                []string
	feed                                      []flowEvent
	demo                                      bool
}

type tickMsg time.Time

type model struct {
	engs   []engagement
	sel    int
	tab    tab
	w, h   int
	demo   bool
	status string
	st     styles
}

// New builds the model from the store, or demo data when the store is empty.
func New() model {
	m := model{st: newStyles(), w: 108, h: 34}
	recs, _ := store.List()
	if len(recs) == 0 {
		m.engs = demoEngagements()
		m.demo = true
	} else {
		for _, r := range recs {
			m.engs = append(m.engs, fromRecord(r))
		}
	}
	for i := range m.engs {
		seedFeed(&m.engs[i])
	}
	return m
}

func (m model) Init() tea.Cmd { return tick() }

func tick() tea.Cmd {
	return tea.Tick(1500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up":
			if m.sel > 0 {
				m.sel--
			}
		case "down":
			if m.sel < len(m.engs)-1 {
				m.sel++
			}
		case "e":
			m.tab = tabEgress
		case "s":
			m.tab = tabScope
		case "tab":
			if m.tab == tabEgress {
				m.tab = tabScope
			} else {
				m.tab = tabEgress
			}
		case "k":
			m.status = (&m).killSelected()
		}
		return m, nil
	case tickMsg:
		for i := range m.engs {
			if m.stateOf(m.engs[i]) == "running" {
				m.engs[i].feed = append(m.engs[i].feed, genEvent(m.engs[i], false))
				if len(m.engs[i].feed) > 200 {
					m.engs[i].feed = m.engs[i].feed[1:]
				}
			}
		}
		return m, tick()
	}
	return m, nil
}

func (m *model) killSelected() string {
	if len(m.engs) == 0 {
		return ""
	}
	e := &m.engs[m.sel]
	if m.stateOf(*e) != "running" {
		return e.name + ": not running"
	}
	if e.demo {
		e.state = "killed"
		e.feed = append(e.feed, flowEvent{ts: time.Now(), proto: "—", dst: "nft delete table inet nullbox", verdict: "drop", note: "egress flushed"})
		return e.name + ": egress flushed (demo)"
	}
	d, err := driver.Get(nbmodel.Driver(e.driver))
	if err != nil {
		return "kill: " + err.Error()
	}
	if err := d.Kill(e.name); err != nil {
		return "kill: " + err.Error()
	}
	e.state = "killed"
	return e.name + ": egress flushed"
}

func (m model) stateOf(e engagement) string {
	if e.state == "running" && e.windowEnd != "" {
		if t, err := time.Parse(time.RFC3339, e.windowEnd); err == nil && time.Now().After(t) {
			return "expired"
		}
	}
	return e.state
}

func (m model) runningCount() int {
	n := 0
	for _, e := range m.engs {
		if m.stateOf(e) == "running" {
			n++
		}
	}
	return n
}
