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

func TestNoForwardChainByDefault(t *testing.T) {
	rs := compile(t, base())
	for _, s := range []string{"hook forward", "guest_egress", "masquerade", "postrouting"} {
		mustNotContain(t, rs.NFT, s)
	}
}

func TestForwardChainWhenEgressIface(t *testing.T) {
	e := base()
	e.Spec.Scope.Allow = []model.Target{{CIDR: "203.0.113.0/24"}}
	e.Spec.Scope.Deny = []model.Target{{CIDR: "203.0.113.99/32"}}
	rs, err := CompileWith(e, Options{EgressIface: "nbx-acme", UplinkIface: "eth0", EnableForward: true})
	if err != nil {
		t.Fatal(err)
	}
	// host output chain is still present (regression) plus the guest forward path.
	mustContain(t, rs.NFT, "type filter hook output priority 0; policy drop;")
	mustContain(t, rs.NFT, "type filter hook forward priority 0; policy accept;")
	mustContain(t, rs.NFT, `iifname "nbx-acme" jump guest_egress`)
	mustContain(t, rs.NFT, `oifname "nbx-acme" accept`) // return traffic to guest
	mustContain(t, rs.NFT, "chain guest_egress {")
	mustContain(t, rs.NFT, "type nat hook postrouting priority srcnat;")
	mustContain(t, rs.NFT, `iifname "nbx-acme" oifname "eth0" masquerade`)

	// deny-by-default for the guest is the terminal drop, not a drop-policy hook.
	ge := rs.NFT[strings.Index(rs.NFT, "chain guest_egress {"):]
	if !strings.Contains(ge, "counter drop") {
		t.Error("guest_egress must end in a terminal counter drop")
	}
	// deny wins inside guest_egress: the deny drop precedes the allow-set accept.
	dIdx := strings.Index(ge, "ip daddr 203.0.113.99/32 drop")
	aIdx := strings.Index(ge, "ip daddr @allow4 accept")
	if dIdx < 0 || aIdx < 0 || dIdx > aIdx {
		t.Errorf("deny must precede allow inside guest_egress (deny=%d allow=%d)", dIdx, aIdx)
	}
}

func TestUplinkDefaultMasquerade(t *testing.T) {
	e := base()
	rs, err := CompileWith(e, Options{EgressIface: "nbx-acme"}) // no uplink
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, rs.NFT, `iifname "nbx-acme" oifname != "nbx-acme" masquerade`)
}

func TestNFLOGGroups(t *testing.T) {
	e := base()
	e.Spec.Scope.Allow = []model.Target{{CIDR: "203.0.113.0/24"}}
	rs := compile(t, e)
	// accept mirrored to the accept group, drop to the drop group.
	mustContain(t, rs.NFT, `log prefix "nullbox-allow " group 331`)
	mustContain(t, rs.NFT, `log prefix "nullbox-drop " group 332`)
	mustContain(t, rs.NFT, "ip daddr @allow4 accept") // verdict line unchanged
	// metadata drop carries the drop group with its note.
	mustContain(t, rs.NFT, `log prefix "nullbox-drop meta " group 332`)
	// established/related and lo are NOT logged.
	for _, line := range strings.Split(rs.NFT, "\n") {
		if strings.Contains(line, "established,related") || strings.Contains(line, `oif "lo"`) {
			if strings.Contains(line, "log") {
				t.Errorf("established/lo line must not log: %q", line)
			}
		}
	}
}

func TestHostFormDenyRejected(t *testing.T) {
	e := base()
	e.Spec.Scope.Deny = []model.Target{{Host: "evil.example.com"}}
	if _, err := Compile(e); err == nil {
		t.Error("a host-form deny must be rejected (not silently ignored -> fail-open)")
	}
}

func TestAllowSetAutoMerge(t *testing.T) {
	mustContain(t, compile(t, base()).NFT, "auto-merge")
}

func TestNatInSeparateIPTable(t *testing.T) {
	rs, err := CompileWith(base(), Options{EgressIface: "nbx-a", UplinkIface: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, rs.NFT, "table ip nullbox {")
	mustContain(t, rs.NFT, "delete table ip nullbox")
	ipIdx := strings.Index(rs.NFT, "table ip nullbox {")
	// masquerade must live in the ip table (inet NAT needs kernel >=5.2)
	inet := rs.NFT[strings.Index(rs.NFT, "table inet nullbox {"):ipIdx]
	if strings.Contains(inet, "masquerade") {
		t.Error("masquerade must NOT be in the inet table")
	}
	if !strings.Contains(rs.NFT[ipIdx:], "masquerade") {
		t.Error("masquerade must be in the ip table")
	}
}
