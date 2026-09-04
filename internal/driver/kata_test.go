package driver

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/policy"
)

func fakeBin(t *testing.T, name string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestKataRegisteredNotStub(t *testing.T) {
	d, err := Get(model.DriverKata)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.(*kataDriver); !ok {
		t.Errorf("Get(kata) = %T, want *kataDriver (stub must be removed)", d)
	}
}

func TestKataPreflightProfiles(t *testing.T) {
	fakeBin(t, "kubectl")
	d := &kataDriver{}
	if err := d.Preflight(model.ProfileRouted); err != nil {
		t.Errorf("routed should pass: %v", err)
	}
	if err := d.Preflight(model.ProfileNAT); err != nil {
		t.Errorf("nat should pass: %v", err)
	}
	if err := d.Preflight(model.ProfileL2); err == nil {
		t.Error("l2 should be rejected (no faithful NetworkPolicy mapping)")
	}
}

func TestKataUpAppliesManifest(t *testing.T) {
	fakeBin(t, "kubectl")
	var applied string
	var sawApply bool
	d := &kataDriver{
		kubectl: func(stdin []byte, args ...string) ([]byte, error) {
			if strings.Join(args, " ") == "apply -f -" {
				sawApply = true
				applied = string(stdin)
			}
			return nil, nil
		},
		resolve: func(string) ([]netip.Addr, error) { return nil, nil },
	}
	e := &model.Engagement{
		Metadata: model.Metadata{Name: "acme"},
		Spec: model.Spec{
			Network: model.Network{Profile: model.ProfileRouted},
			Scope:   model.Scope{Allow: []model.Target{{CIDR: "10.10.0.0/16"}}},
		},
	}
	st, err := d.Up(UpSpec{Engagement: e, ImageRef: "img", Ruleset: &policy.Ruleset{}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Driver != model.DriverKata || st.State != "running" {
		t.Errorf("status %+v", st)
	}
	if !sawApply {
		t.Fatal("expected kubectl apply -f -")
	}
	if !strings.Contains(applied, "runtimeClassName: kata") || !strings.Contains(applied, "kind: NetworkPolicy") {
		t.Errorf("applied manifest looks wrong:\n%s", applied)
	}
}

func TestKataKillLockdownThenDeletesScope(t *testing.T) {
	var lockApplied string
	deletedScope := false
	d := &kataDriver{kubectl: func(stdin []byte, args ...string) ([]byte, error) {
		j := strings.Join(args, " ")
		if strings.Contains(j, "apply") && stdin != nil {
			lockApplied = string(stdin)
		}
		if strings.Contains(j, "delete networkpolicy nbx-scope") {
			deletedScope = true
		}
		return nil, nil
	}}
	if err := d.Kill("acme"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lockApplied, "nbx-deny-all") || !strings.Contains(lockApplied, "egress: []") {
		t.Errorf("Kill should apply a deny-all lockdown:\n%s", lockApplied)
	}
	// NetworkPolicies are additive: the allow policy must be removed or the
	// deny-all is a no-op.
	if !deletedScope {
		t.Error("Kill must delete the nbx-scope allow policy")
	}
}
