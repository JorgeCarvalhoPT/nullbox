package tui

import (
	"os"
	"path/filepath"
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
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func typeStr(m model, s string) model {
	for _, r := range s {
		if r == ' ' {
			m = send(m, tea.KeyMsg{Type: tea.KeySpace})
		} else {
			m = send(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		}
	}
	return m
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

func mouseClick(x, y int) tea.MouseMsg {
	return tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: x, Y: y}
}

func TestClickSelectsCard(t *testing.T) {
	m := demoModel(t)                                          // 3 demo engagements, sel 0
	m = send(m, mouseClick(3, tuiHeaderLines+tuiCardHeight+1)) // a body row of card 1
	if m.sel != 1 {
		t.Errorf("click should select card 1, got sel=%d", m.sel)
	}
}

func TestClickStopRemovesDemoCard(t *testing.T) {
	m := demoModel(t)
	before := len(m.engs) // card 0 (acme-internal) is running
	// acts row of card 0, x in the stop-verb range
	m = send(m, mouseClick(3, tuiHeaderLines+tuiActsRow))
	if len(m.engs) != before-1 {
		t.Errorf("clicking stop should remove the demo card: %d -> %d", before, len(m.engs))
	}
}

func TestClickExecVerbDemo(t *testing.T) {
	m := demoModel(t)
	// exec verb (middle third) on card 0
	m = send(m, mouseClick(10, tuiHeaderLines+tuiActsRow))
	if !strings.Contains(m.status, "exec") {
		t.Errorf("clicking exec should set an exec status, got %q", m.status)
	}
	if len(m.engs) != 3 {
		t.Error("exec must not remove the card")
	}
}

func TestKeyStopAndExec(t *testing.T) {
	m := demoModel(t)
	before := len(m.engs)
	m = send(m, key("d")) // stop the running card 0
	if len(m.engs) != before-1 {
		t.Error("`d` should stop/remove the running demo card")
	}
	m2 := demoModel(t)
	m2 = send(m2, key("x")) // exec
	if !strings.Contains(m2.status, "exec") {
		t.Errorf("`x` should set an exec status, got %q", m2.status)
	}
}

func TestClickRemoveNonRunning(t *testing.T) {
	m := demoModel(t)
	// card 2 (beta-scan) is killed; select + click remove (right third)
	m = send(m, mouseClick(16, tuiHeaderLines+2*tuiCardHeight+tuiActsRow))
	// beta-scan removed
	for _, e := range m.engs {
		if e.name == "beta-scan" {
			t.Error("clicking remove on the killed card should remove it")
		}
	}
}

func TestNewEngagementFormScaffolds(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	m := demoModel(t)
	m = send(m, key("n"))
	if m.mode != modeForm {
		t.Fatal("`n` should open the new-engagement form")
	}
	m = typeStr(m, "acme-new") // field 0: name
	m = send(m, key("tab"))
	m = send(m, key("tab")) // field 2: auth ref
	m = typeStr(m, "SOW-9")
	for i := 0; i < 5; i++ { // -> field 7: allow
		m = send(m, key("tab"))
	}
	m = typeStr(m, "10.0.0.0/8")
	m = send(m, key("enter")) // submit
	if m.form.err != "" {
		t.Fatalf("unexpected form error: %s", m.form.err)
	}
	if m.mode != modeConfirm {
		t.Fatalf("submit should go to the boot? confirm, mode=%d", m.mode)
	}
	if _, err := os.Stat(filepath.Join(dir, "acme-new.yaml")); err != nil {
		t.Errorf("manifest was not written: %v", err)
	}
	m = send(m, key("n")) // keep manifest, do not boot
	if m.mode != modeList {
		t.Error("confirm `n` should return to the list")
	}
}

func TestFormRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(old)
	m := demoModel(t)
	m = send(m, key("n"))
	// submit an empty form -> validation error, stays in the form
	m = send(m, key("enter"))
	if m.mode != modeForm || m.form.err == "" {
		t.Errorf("empty form must show an error and stay open (mode=%d err=%q)", m.mode, m.form.err)
	}
}
