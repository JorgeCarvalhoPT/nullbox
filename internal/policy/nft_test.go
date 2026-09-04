package policy

import (
	"strings"
	"testing"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

func boolPtr(b bool) *bool { return &b }

// base returns a valid engagement with one all-ports CIDR in scope.
func base() *model.Engagement {
	return &model.Engagement{
		APIVersion: "nullbox/v1",
		Kind:       "Engagement",
		Metadata: model.Metadata{
			Name:          "acme",
			Authorization: model.Authorization{Ref: "SOW-1"},
		},
		Spec: model.Spec{
			Window:  model.Window{End: "2026-12-31T00:00:00Z"},
			Network: model.Network{Profile: model.ProfileRouted},
			Scope: model.Scope{
				Allow: []model.Target{{CIDR: "203.0.113.0/24"}},
			},
		},
	}
}

func compile(t *testing.T, e *model.Engagement) *Ruleset {
	t.Helper()
	rs, err := Compile(e)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return rs
}

func mustContain(t *testing.T, hay, needle string) {
	t.Helper()
	if !strings.Contains(hay, needle) {
		t.Errorf("expected ruleset to contain %q\n--- ruleset ---\n%s", needle, hay)
	}
}

func mustNotContain(t *testing.T, hay, needle string) {
	t.Helper()
	if strings.Contains(hay, needle) {
		t.Errorf("expected ruleset NOT to contain %q\n--- ruleset ---\n%s", needle, hay)
	}
}

func TestDenyByDefaultAndIdempotentApply(t *testing.T) {
	rs := compile(t, base())
	mustContain(t, rs.NFT, "type filter hook output priority 0; policy drop;")
	mustContain(t, rs.NFT, "delete table inet nullbox") // idempotent re-apply
	mustContain(t, rs.NFT, "counter drop")
	mustContain(t, rs.NFT, `log prefix "nullbox-drop `)
}

func TestMetadataDeniedByDefault(t *testing.T) {
	rs := compile(t, base())
	mustContain(t, rs.NFT, "ip daddr 169.254.169.254 drop")
	mustContain(t, rs.NFT, "ip daddr 169.254.0.0/16 drop")
}

func TestMetadataOptOut(t *testing.T) {
	e := base()
	e.Spec.Network.DenyMetadata = boolPtr(false)
	rs := compile(t, e)
	mustNotContain(t, rs.NFT, "169.254.169.254")
}

func TestUnportedCIDRGoesInAllowSet(t *testing.T) {
	rs := compile(t, base())
	mustContain(t, rs.NFT, "elements = { 203.0.113.0/24 }")
	mustContain(t, rs.NFT, "ip daddr @allow4 accept")
}

// The critical one: a port-scoped target must be restricted to its ports and
// must NOT be swept into the all-ports @allow4 set.
func TestPortedCIDRIsPortRestrictedAndNotInSet(t *testing.T) {
	e := base()
	e.Spec.Scope.Allow = []model.Target{{CIDR: "10.0.0.0/24", Ports: []int{8443, 443}}}
	rs := compile(t, e)
	mustContain(t, rs.NFT, "ip daddr 10.0.0.0/24 tcp dport { 443, 8443 } accept")
	mustContain(t, rs.NFT, "ip daddr 10.0.0.0/24 udp dport { 443, 8443 } accept")
	// Must not appear in the allow-all set.
	mustNotContain(t, rs.NFT, "elements = { 10.0.0.0/24 }")
}

// Mixed: one unported + one ported prefix. The unported is in the set, the
// ported is not.
func TestMixedPortedAndUnported(t *testing.T) {
	e := base()
	e.Spec.Scope.Allow = []model.Target{
		{CIDR: "203.0.113.0/24"},
		{CIDR: "10.0.0.0/24", Ports: []int{443}},
	}
	rs := compile(t, e)
	mustContain(t, rs.NFT, "elements = { 203.0.113.0/24 }")
	mustContain(t, rs.NFT, "ip daddr 10.0.0.0/24 tcp dport { 443 } accept")
	if strings.Contains(rs.NFT, "10.0.0.0/24 }") && strings.Contains(rs.NFT, "elements = {") {
		// crude guard: the ported prefix must not be inside the elements list
		el := rs.NFT[strings.Index(rs.NFT, "elements = {"):]
		el = el[:strings.Index(el, "}")]
		if strings.Contains(el, "10.0.0.0/24") {
			t.Errorf("ported prefix leaked into allow4 set: %q", el)
		}
	}
}

func TestDenyWinsOrdering(t *testing.T) {
	e := base()
	e.Spec.Scope.Allow = []model.Target{{CIDR: "203.0.113.0/24"}}
	e.Spec.Scope.Deny = []model.Target{{CIDR: "203.0.113.99/32"}}
	rs := compile(t, e)
	denyIdx := strings.Index(rs.NFT, "ip daddr 203.0.113.99/32 drop")
	allowIdx := strings.Index(rs.NFT, "ip daddr @allow4 accept")
	if denyIdx < 0 {
		t.Fatalf("deny rule missing")
	}
	if allowIdx < 0 {
		t.Fatalf("allow rule missing")
	}
	if denyIdx > allowIdx {
		t.Errorf("deny rule (%d) must precede allow rule (%d) so deny wins", denyIdx, allowIdx)
	}
}

func TestHostTargetsAreUnresolvedAndOpenDNS(t *testing.T) {
	e := base()
	e.Spec.Scope.Allow = []model.Target{{Host: "api.example.com", Ports: []int{443}}}
	rs := compile(t, e)
	mustContain(t, rs.NFT, "udp dport 53 accept")
	mustContain(t, rs.NFT, "tcp dport 53 accept")
	if len(rs.UnresolvedHosts) != 1 || rs.UnresolvedHosts[0].Host != "api.example.com" {
		t.Fatalf("expected api.example.com in UnresolvedHosts, got %+v", rs.UnresolvedHosts)
	}
	// No host target => no DNS opening.
	rs2 := compile(t, base())
	mustNotContain(t, rs2.NFT, "dport 53 accept")
	if len(rs2.UnresolvedHosts) != 0 {
		t.Errorf("expected no unresolved hosts, got %+v", rs2.UnresolvedHosts)
	}
}
