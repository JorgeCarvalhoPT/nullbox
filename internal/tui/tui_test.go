package tui

import (
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func strip(s string) string { return ansi.ReplaceAllString(s, "") }

func send(m model, msg tea.Msg) model {
	next, _ := m.Update(msg)
	return next.(model)
}
func key(s string) tea.KeyMsg {
	switch s {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func demoModel(t *testing.T) model {
	t.Helper()
	t.Setenv("NULLBOX_STATE", t.TempDir()) // empty store -> demo data
	m := New()
	m = send(m, tea.WindowSizeMsg{Width: 118, Height: 40})
	return m
}

func TestInitialViewRenders(t *testing.T) {
	m := demoModel(t)
	if len(m.engs) != 3 {
		t.Fatalf("expected 3 demo engagements, got %d", len(m.engs))
	}
	v := strip(m.View())
	for _, want := range []string{"nullbox", "acme-internal", "microVM", "AI pentest agent", "Egress Log", "Scope Rules", "Last seen", "Destination", "Allowed"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q", want)
		}
	}
	t.Logf("\n%s", v) // eyeball with -v
}

func TestScopeTab(t *testing.T) {
	m := demoModel(t)
	m = send(m, key("s"))
	v := strip(m.View())
	if !strings.Contains(v, "10.10.0.0/16") || !strings.Contains(v, "allow") || !strings.Contains(v, "169.254.169.254") {
		t.Errorf("scope tab should list allow rules + the metadata deny; got:\n%s", v)
	}
	if !strings.Contains(v, "deny-by-default") {
		t.Errorf("scope tab should note deny-by-default")
	}
}

func TestSelectDown(t *testing.T) {
	m := demoModel(t)
	if m.sel != 0 {
		t.Fatalf("sel should start at 0")
	}
	m = send(m, key("down"))
	if m.sel != 1 {
		t.Errorf("down should move selection to 1, got %d", m.sel)
	}
}

func TestKillDemo(t *testing.T) {
	m := demoModel(t) // sel 0 = acme-internal, running
	m = send(m, key("k"))
	if got := m.stateOf(m.engs[0]); got != "killed" {
		t.Fatalf("kill should flip demo engagement to killed, got %q", got)
	}
	if !strings.Contains(m.status, "flushed") {
		t.Errorf("status should report flush, got %q", m.status)
	}
	if !strings.Contains(strip(m.View()), "nft table deleted") {
		t.Errorf("killed pane should show the flushed banner")
	}
}

func TestTickGrowsFeed(t *testing.T) {
	m := demoModel(t)
	before := len(m.engs[0].feed)
	m = send(m, tickMsg{})
	if len(m.engs[0].feed) != before+1 {
		t.Errorf("tick should append one event to a running engagement (%d -> %d)", before, len(m.engs[0].feed))
	}
	// a stopped engagement (beta-scan) gets none
	if len(m.engs[2].feed) != 0 {
		t.Errorf("stopped engagement should not accrue events")
	}
}
