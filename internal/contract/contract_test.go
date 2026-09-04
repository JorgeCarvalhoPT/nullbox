package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

func eng(profile model.Profile, infra bool) *model.Engagement {
	return &model.Engagement{
		APIVersion: "nullbox/v1", Kind: "Engagement",
		Metadata: model.Metadata{Name: "acme", Client: "ACME Corp", Authorization: model.Authorization{Ref: "SOW-1"}},
		Spec: model.Spec{
			Window:       model.Window{End: "2026-12-31T00:00:00Z"},
			Network:      model.Network{Profile: profile},
			Capabilities: model.Capabilities{InfraTools: infra},
			Scope: model.Scope{
				Allow: []model.Target{
					{CIDR: "10.10.0.0/16"},
					{CIDR: "10.20.5.0/24", Ports: []int{443, 8443}},
					{Host: "portal.acme.example"},
					{Host: "*.staging.acme.example"},
				},
				Deny: []model.Target{{CIDR: "10.10.9.0/24"}},
			},
		},
	}
}

func mustHave(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("contract missing %q", sub)
	}
}
func mustNot(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Errorf("contract should not contain %q", sub)
	}
}

func TestGroundRulesAlwaysPresent(t *testing.T) {
	for _, p := range []model.Profile{model.ProfileNAT, model.ProfileRouted, model.ProfileL2} {
		s := Generate(eng(p, false))
		mustHave(t, s, "DENY-BY-DEFAULT")
		mustHave(t, s, "is NOT evidence of a clean result")
		mustHave(t, s, "NEVER close a coverage")
		mustHave(t, s, "OUT-OF-SCOPE")
	}
}

func TestHeader(t *testing.T) {
	s := Generate(eng(model.ProfileRouted, false))
	mustHave(t, s, "acme")
	mustHave(t, s, "ACME Corp")
	mustHave(t, s, "SOW-1")
	mustHave(t, s, "2026-12-31T00:00:00Z")
}

func TestNATProfile(t *testing.T) {
	s := Generate(eng(model.ProfileNAT, false))
	mustHave(t, s, "nmap -sT")
	mustHave(t, s, "nmap -sS")
	mustHave(t, s, "arp-scan")
	mustHave(t, s, "Responder")
	mustHave(t, s, "mitm6")
	mustHave(t, s, "PROFILE limit, not a target result")
}

func TestRoutedProfile(t *testing.T) {
	s := Generate(eng(model.ProfileRouted, true))
	mustHave(t, s, "-sS")
	mustHave(t, s, "-sU")
	mustHave(t, s, "masscan")
	mustHave(t, s, "hping3")
	mustHave(t, s, "NOT on their broadcast domain")
}

func TestL2Profile(t *testing.T) {
	s := Generate(eng(model.ProfileL2, true))
	mustHave(t, s, "everything routed gives, PLUS")
	mustHave(t, s, "placement-bound")
	mustHave(t, s, "Responder")
}

func TestMetadataBranch(t *testing.T) {
	// default (unset) => blocked
	s := Generate(eng(model.ProfileNAT, false))
	mustHave(t, s, "OUT OF SCOPE")
	mustNot(t, s, "is REACHABLE")

	// denyMetadata=false => reachable + in scope
	e := eng(model.ProfileNAT, false)
	f := false
	e.Spec.Network.DenyMetadata = &f
	s2 := Generate(e)
	mustHave(t, s2, "is REACHABLE")
	mustHave(t, s2, "authorized IMDS test is IN SCOPE")
}

func TestScopeRendering(t *testing.T) {
	s := Generate(eng(model.ProfileRouted, false))
	mustHave(t, s, "10.10.0.0/16 (all ports)")
	mustHave(t, s, "10.20.5.0/24 (tcp/udp 443, 8443)")
	mustHave(t, s, "portal.acme.example (host, resolved at apply time)")
	mustHave(t, s, "*.staging.acme.example (wildcard host, SNI-scoped)")
	mustHave(t, s, "10.10.9.0/24 (whole prefix dropped")
}

func TestEmptyDeny(t *testing.T) {
	e := eng(model.ProfileNAT, false)
	e.Spec.Scope.Deny = nil
	s := Generate(e)
	// The Denied section must show (none).
	i := strings.Index(s, "Denied")
	if i < 0 || !strings.Contains(s[i:], "- (none)") {
		t.Errorf("empty deny should render '- (none)' in the Denied section")
	}
}

func TestTooling(t *testing.T) {
	mustHave(t, Generate(eng(model.ProfileRouted, true)), "FULL image")
	mustHave(t, Generate(eng(model.ProfileRouted, false)), "absent in the thin image")
	mustHave(t, Generate(eng(model.ProfileNAT, true)), "of limited use")
}

func TestWriteInto(t *testing.T) {
	home := t.TempDir()
	path, err := WriteInto(home, eng(model.ProfileNAT, false))
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(home, ".claude", "CLAUDE.md") {
		t.Errorf("unexpected path %q", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "nullbox engagement contract") {
		t.Errorf("written file missing contract body")
	}
}
