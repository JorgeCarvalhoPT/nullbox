// Package tui is nullbox's in-terminal interface, built on
// the same stack (charmbracelet/bubbletea + lipgloss). It lives in the terminal:
// `nullbox` with no arguments launches it. Left column lists engagements; the
// right pane shows the live egress log (allowed vs dropped) and the compiled
// scope rules; the bottom bar carries the key hints. It reads the engagement
// store, and falls back to demo data when the store is empty so the interface
// is populated on first run (marked "demo").
package tui

import (
	"os"
	"os/exec"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/JorgeCarvalhoPT/nullbox/internal/driver"
	nbmodel "github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/store"
)

// Run launches the TUI (full-screen, alternate buffer, mouse enabled).
func Run() error {
	_, err := tea.NewProgram(New(), tea.WithAltScreen(), tea.WithMouseCellMotion()).Run()
	return err
}

type tab int

const (
	tabEgress tab = iota
	tabScope
)

// Layout geometry for click hit-testing on the left card column. Kept in sync
// with view.go: the View opens with a blank line + titlebar + rule + appbar +
// rule + blank (6 rows) before the body; each card is 8 rows (rounded border +
// 6 content lines), and the "stop/exec/kill" action row is the 7th (index 6).
const (
	tuiHeaderLines = 6
	tuiCardHeight  = 8
	tuiListWidth   = 36
	tuiActsRow     = 6
)

type reloadMsg struct{}
type execDoneMsg struct{ err error }

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
	mode   int // modeList | modeForm | modeConfirm
	form   formState
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
	case tea.MouseMsg:
		if m.mode == modeList && msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
			return m.handleClick(msg.X, msg.Y)
		}
		return m, nil
	case bootDoneMsg:
		if msg.err != nil {
			m.status = msg.name + ": boot failed: " + msg.err.Error()
		} else {
			m.status = msg.name + ": up"
			(&m).reload()
		}
		return m, nil
	case tea.KeyMsg:
		if m.mode == modeForm {
			return m.updateForm(msg)
		}
		if m.mode == modeConfirm {
			return m.updateConfirm(msg)
		}
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "n": // new engagement
			m.mode = modeForm
			m.form = newForm()
			return m, nil
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
		case "x": // exec — attach a shell
			return m, (&m).execSelected()
		case "d": // stop (down) the running engagement
			if len(m.engs) > 0 && m.stateOf(m.engs[m.sel]) == "running" {
				cmd, status := (&m).stopSelected()
				m.status = status
				return m, cmd
			}
		case "k": // kill — flush egress (panic)
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
	case reloadMsg:
		(&m).reload()
		return m, nil
	case execDoneMsg:
		m.status = ""
		if msg.err != nil {
			m.status = "exec: " + msg.err.Error()
		}
		return m, nil
	}
	return m, nil
}

// handleClick maps a left-click to card selection or a "stop/exec/kill" verb.
func (m model) handleClick(x, y int) (tea.Model, tea.Cmd) {
	if x < 0 || x >= tuiListWidth || y < tuiHeaderLines {
		return m, nil
	}
	localY := y - tuiHeaderLines
	idx := localY / tuiCardHeight
	if idx < 0 || idx >= len(m.engs) {
		return m, nil
	}
	m.sel = idx // clicking anywhere on a card selects it
	if localY%tuiCardHeight != tuiActsRow {
		return m, nil
	}
	verb := -1
	switch {
	case x >= 2 && x < 8:
		verb = 0 // stop / start
	case x >= 8 && x < 14:
		verb = 1 // exec
	case x >= 14 && x < 24:
		verb = 2 // kill / remove
	}
	return m.triggerVerb(verb)
}

// triggerVerb runs a card action for the selected engagement.
func (m model) triggerVerb(verb int) (tea.Model, tea.Cmd) {
	if len(m.engs) == 0 || verb < 0 {
		return m, nil
	}
	running := m.stateOf(m.engs[m.sel]) == "running"
	switch {
	case verb == 1: // exec works in either state
		return m, (&m).execSelected()
	case running && verb == 0: // stop
		cmd, status := (&m).stopSelected()
		m.status = status
		return m, cmd
	case running && verb == 2: // kill
		m.status = (&m).killSelected()
	case !running && verb == 2: // remove
		m.status = (&m).removeSelected()
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

// stopSelected stops (tears down) the running engagement. Demo cards are removed
// in-memory; live ones Down the driver + forget the record, then reload.
func (m *model) stopSelected() (tea.Cmd, string) {
	if len(m.engs) == 0 {
		return nil, ""
	}
	e := m.engs[m.sel]
	if m.stateOf(e) != "running" {
		return nil, e.name + ": not running"
	}
	if e.demo {
		name := e.name
		m.removeCard(m.sel)
		return nil, name + ": stopped (demo)"
	}
	name, drv := e.name, e.driver
	return func() tea.Msg {
		if d, err := driver.Get(nbmodel.Driver(drv)); err == nil {
			_ = d.Down(name)
		}
		_ = store.Delete(name)
		return reloadMsg{}
	}, name + ": stopping…"
}

// execSelected attaches an interactive shell by suspending the TUI and running
// `nullbox shell <name>` (which itself calls the driver's Shell).
func (m *model) execSelected() tea.Cmd {
	if len(m.engs) == 0 {
		return nil
	}
	e := m.engs[m.sel]
	if e.demo {
		m.status = e.name + ": exec would attach a shell (demo)"
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		self = "nullbox"
	}
	c := exec.Command(self, "shell", e.name)
	return tea.ExecProcess(c, func(err error) tea.Msg { return execDoneMsg{err} })
}

// removeSelected forgets a non-running engagement.
func (m *model) removeSelected() string {
	if len(m.engs) == 0 {
		return ""
	}
	e := m.engs[m.sel]
	if !e.demo {
		_ = store.Delete(e.name)
	}
	m.removeCard(m.sel)
	return e.name + ": removed"
}

func (m *model) removeCard(i int) {
	m.engs = append(m.engs[:i], m.engs[i+1:]...)
	if m.sel >= len(m.engs) && m.sel > 0 {
		m.sel--
	}
}

// reload rebuilds the engagement list from the store, preserving feeds by name.
func (m *model) reload() {
	recs, _ := store.List()
	old := map[string]engagement{}
	for _, e := range m.engs {
		old[e.name] = e
	}
	var engs []engagement
	for _, r := range recs {
		e := fromRecord(r)
		if o, ok := old[e.name]; ok {
			e.feed = o.feed
		}
		engs = append(engs, e)
	}
	m.engs = engs
	m.demo = false
	if m.sel >= len(m.engs) {
		m.sel = 0
		if len(m.engs) > 0 {
			m.sel = len(m.engs) - 1
		}
	}
	for i := range m.engs {
		seedFeed(&m.engs[i])
	}
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
