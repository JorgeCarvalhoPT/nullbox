package driver

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

func renderScope(t *testing.T, allow, deny []model.Target, resolved map[string][]netip.Addr) string {
	t.Helper()
	e := &model.Engagement{
		Metadata: model.Metadata{Name: "acme"},
		Spec: model.Spec{
			Network: model.Network{Profile: model.ProfileRouted},
			Scope:   model.Scope{Allow: allow, Deny: deny},
		},
	}
	b, err := renderManifests(UpSpec{Engagement: e, ImageRef: "nullbox/smith:full"}, resolved)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRenderPodAndPolicyShape(t *testing.T) {
	m := renderScope(t, []model.Target{{CIDR: "203.0.113.0/24"}}, nil, nil)
	for _, want := range []string{
		"kind: Namespace", "kind: Pod", "kind: NetworkPolicy",
		"runtimeClassName: kata", "image: nullbox/smith:full",
		"NET_ADMIN", "NET_RAW", "mountPath: /var/lib/docker", "emptyDir:",
		"policyTypes:", "- Egress", "cidr: 203.0.113.0/24",
		"nbx-acme", // namespace
	} {
		if !strings.Contains(m, want) {
			t.Errorf("manifest missing %q", want)
		}
	}
}

func TestRenderDenyWithinAllowBecomesExcept(t *testing.T) {
	m := renderScope(t,
		[]model.Target{{CIDR: "10.10.0.0/16"}},
		[]model.Target{{CIDR: "10.10.9.0/24"}}, nil)
	if !strings.Contains(m, "cidr: 10.10.0.0/16") {
		t.Error("allow block missing")
	}
	if !strings.Contains(m, "except:") || !strings.Contains(m, "10.10.9.0/24") {
		t.Errorf("deny-within-allow should appear in ipBlock.except:\n%s", m)
	}
}

func TestRenderDenyCoveringAllowDropsRule(t *testing.T) {
	m := renderScope(t,
		[]model.Target{{CIDR: "10.10.0.0/24"}},
		[]model.Target{{CIDR: "10.10.0.0/16"}}, nil)
	if strings.Contains(m, "cidr: 10.10.0.0/24") {
		t.Errorf("a deny covering the allow should drop the rule entirely:\n%s", m)
	}
}

func TestRenderMetadataNotInNormalAllow(t *testing.T) {
	m := renderScope(t, []model.Target{{CIDR: "203.0.113.0/24"}}, nil, nil)
	if strings.Contains(m, "169.254.169.254") {
		t.Error("metadata must not appear for a normal target (denied by default-deny)")
	}
}

func TestRenderMetadataExceptForBroadAllow(t *testing.T) {
	m := renderScope(t, []model.Target{{CIDR: "0.0.0.0/0"}}, nil, nil)
	if !strings.Contains(m, "169.254.169.254/32") {
		t.Errorf("an over-broad allow must carve out metadata via except:\n%s", m)
	}
}

func TestRenderPortedCIDR(t *testing.T) {
	m := renderScope(t, []model.Target{{CIDR: "10.20.5.0/24", Ports: []int{443}}}, nil, nil)
	if !strings.Contains(m, "protocol: TCP") || !strings.Contains(m, "protocol: UDP") || !strings.Contains(m, "port: 443") {
		t.Errorf("ported CIDR should yield TCP+UDP port entries:\n%s", m)
	}
}

func TestRenderDNSOnlyWithHosts(t *testing.T) {
	noHost := renderScope(t, []model.Target{{CIDR: "10.0.0.0/8"}}, nil, nil)
	if strings.Contains(noHost, "k8s-app: kube-dns") {
		t.Error("no DNS rule should appear without host targets")
	}
	withHost := renderScope(t, []model.Target{{Host: "api.example.com"}},
		nil, map[string][]netip.Addr{"api.example.com": {netip.MustParseAddr("93.184.216.34")}})
	if !strings.Contains(withHost, "k8s-app: kube-dns") {
		t.Error("DNS rule expected when hosts are in scope")
	}
	if !strings.Contains(withHost, "cidr: 93.184.216.34/32") {
		t.Error("resolved host addr should be a /32 allow")
	}
}

func TestExceptsFor(t *testing.T) {
	a := netip.MustParsePrefix("10.10.0.0/16")
	// deny within allow
	ex, drop := exceptsFor(a, []netip.Prefix{netip.MustParsePrefix("10.10.9.0/24")})
	if drop || len(ex) != 1 || ex[0] != "10.10.9.0/24" {
		t.Errorf("within-allow: %v drop=%v", ex, drop)
	}
	// deny covering allow
	_, drop = exceptsFor(netip.MustParsePrefix("10.10.0.0/24"), []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")})
	if !drop {
		t.Error("covering deny should drop")
	}
	// disjoint deny => no effect
	ex, drop = exceptsFor(a, []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
	if drop || len(ex) != 0 {
		t.Errorf("disjoint deny should be a no-op: %v", ex)
	}
}

// The scope NetworkPolicy must select ALL pods in the namespace (podSelector {})
// so sibling tool Job pods (component=tool) are also scoped — not fail-open.
func TestRenderScopePolicySelectsAllPods(t *testing.T) {
	m := renderScope(t, []model.Target{{CIDR: "10.0.0.0/8"}}, nil, nil)
	if !strings.Contains(m, "podSelector: {}") {
		t.Errorf("scope NetworkPolicy must select all pods (podSelector: {}) so tool pods are scoped:\n%s", m)
	}
}

func TestRenderResolvedHostRespectsDeny(t *testing.T) {
	m := renderScope(t,
		[]model.Target{{CIDR: "10.0.0.0/8"}, {Host: "h.example.com"}},
		[]model.Target{{CIDR: "10.1.0.0/16"}},
		map[string][]netip.Addr{"h.example.com": {netip.MustParseAddr("10.1.2.3")}})
	if strings.Contains(m, "10.1.2.3/32") {
		t.Errorf("a resolved host inside a deny prefix must not be admitted:\n%s", m)
	}
}

func TestRenderAllowEqualLinkLocalDropped(t *testing.T) {
	// allow == link-local/16 under denyMetadata must DROP the rule, never emit
	// an except equal to the cidr (which the API server rejects).
	e := &model.Engagement{
		Metadata: model.Metadata{Name: "acme"},
		Spec: model.Spec{
			Network: model.Network{Profile: model.ProfileRouted},
			Scope:   model.Scope{Allow: []model.Target{{CIDR: "169.254.0.0/16"}}},
		},
	}
	b, err := renderManifests(UpSpec{Engagement: e, ImageRef: "img"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "cidr: 169.254.0.0/16") {
		t.Errorf("an allow equal to link-local must be dropped under denyMetadata:\n%s", b)
	}
}
