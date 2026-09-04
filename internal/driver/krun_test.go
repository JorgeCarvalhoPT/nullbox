package driver

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/policy"
)

func TestKrunCreateArgs(t *testing.T) {
	got := krunCreateArgs("nbx-acme", "nullbox/smith:thin", "/ws", "/cfg", 7788, 2, 2048)
	want := "create --name nbx-acme --cpus 2 --mem 2048 --volume /cfg:/etc/nullbox --volume /ws:/workspace --workdir /workspace --port 7788:7788 nullbox/smith:thin"
	if strings.Join(got, " ") != want {
		t.Errorf("createArgs =\n %q\nwant\n %q", strings.Join(got, " "), want)
	}
}

func TestKrunCreateArgsMinimal(t *testing.T) {
	got := krunCreateArgs("nbx-x", "img", "", "/cfg", 0, 2, 2048)
	j := strings.Join(got, " ")
	if strings.Contains(j, "--workdir") || strings.Contains(j, "--port") {
		t.Errorf("no workspace/port should omit those flags: %v", got)
	}
	if got[len(got)-1] != "img" {
		t.Errorf("image must be last arg: %v", got)
	}
}

func TestKrunStartArgs(t *testing.T) {
	if strings.Join(krunStartArgs("nbx-acme"), " ") != "start nbx-acme" {
		t.Error("start args wrong")
	}
	if strings.Join(krunStartArgs("nbx-acme", "/bin/bash", "-l"), " ") != "start nbx-acme /bin/bash -l" {
		t.Error("start args with cmd wrong")
	}
}

func TestFreeTCPPort(t *testing.T) {
	if p, err := freeTCPPort(); err != nil || p <= 0 {
		t.Fatalf("freeTCPPort = %d, %v", p, err)
	}
}

func TestPidfileRoundTrip(t *testing.T) {
	t.Setenv("NULLBOX_STATE", t.TempDir())
	if err := writePidfile("acme", 12345); err != nil {
		t.Fatal(err)
	}
	if pid, err := readPidfile("acme"); err != nil || pid != 12345 {
		t.Fatalf("readPidfile = %d, %v", pid, err)
	}
	removePidfile("acme")
	if _, err := readPidfile("acme"); err == nil {
		t.Error("pidfile should be gone")
	}
}

// fakeKrunvm writes a dummy krunvm onto PATH so Preflight's LookPath passes.
func fakeKrunvm(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "krunvm"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestKrunUpThroughSeams(t *testing.T) {
	t.Setenv("NULLBOX_STATE", t.TempDir())
	fakeKrunvm(t)

	var calls [][]string
	d := &krunDriver{
		run:     func(c *exec.Cmd) ([]byte, error) { calls = append(calls, c.Args); return nil, nil },
		startVM: func(vm, logDir string) (int, error) { return 4242, nil },
		resolve: func(host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
	}
	e := &model.Engagement{
		Metadata: model.Metadata{Name: "acme"},
		Spec: model.Spec{
			Network: model.Network{Profile: model.ProfileNAT},
			Scope:   model.Scope{Allow: []model.Target{{Host: "example.com"}}},
		},
	}
	rs, _ := policy.Compile(e)
	st, err := d.Up(UpSpec{Engagement: e, Ruleset: rs, ImageRef: "nullbox/smith:thin"})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if st.State != "running" || st.MCPPort == 0 || st.Driver != model.DriverKrun {
		t.Errorf("bad status: %+v", st)
	}
	sawCreate := false
	for _, c := range calls {
		if len(c) > 1 && c[0] == "krunvm" && c[1] == "create" {
			sawCreate = true
		}
	}
	if !sawCreate {
		t.Errorf("expected a krunvm create call, got %v", calls)
	}
	if pid, err := readPidfile("acme"); err != nil || pid != 4242 {
		t.Errorf("pidfile pid=%d err=%v", pid, err)
	}
	// the resolved host IP was folded into the policy bundle
	bundle := filepath.Join(krunRunDir(), "acme", "policy.nft")
	data, err := os.ReadFile(bundle)
	if err != nil || !strings.Contains(string(data), "93.184.216.34") {
		t.Errorf("policy bundle missing resolved host addr: %v", err)
	}
}

func TestKrunKillThroughSeam(t *testing.T) {
	t.Setenv("NULLBOX_STATE", t.TempDir())
	_ = writePidfile("acme", 999999) // nonexistent pgid so syscall.Kill is a harmless ESRCH
	pkilled := false
	d := &krunDriver{run: func(c *exec.Cmd) ([]byte, error) {
		if len(c.Args) > 0 && c.Args[0] == "pkill" {
			pkilled = true
		}
		return nil, nil
	}}
	if err := d.Kill("acme"); err != nil {
		t.Fatal(err)
	}
	if !pkilled {
		t.Error("Kill should invoke pkill via the seam")
	}
	if _, err := readPidfile("acme"); err == nil {
		t.Error("Kill should remove the pidfile")
	}
}
