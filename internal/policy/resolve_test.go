package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

func fakeResolver(m map[string][]string) Resolver {
	return func(host string) ([]netip.Addr, error) {
		ips, ok := m[host]
		if !ok {
			return nil, fmt.Errorf("NXDOMAIN")
		}
		var out []netip.Addr
		for _, s := range ips {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
}

func TestResolveHostRules(t *testing.T) {
	hosts := []HostRule{
		{Host: "api.example.com"},                      // resolves to v4 -> add element
		{Host: "dual.example.com"},                     // v4 + v6 -> only v4 admitted
		{Host: "*.staging.example.com"},                // wildcard -> skipped
		{Host: "admin.example.com", Ports: []int{443}}, // ported host -> skipped
		{Host: "gone.example.com"},                     // NXDOMAIN -> skipped
	}
	r := fakeResolver(map[string][]string{
		"api.example.com":  {"203.0.113.10"},
		"dual.example.com": {"203.0.113.20", "2001:db8::1"},
	})

	res, err := ResolveHostRules(hosts, r)
	if err != nil {
		t.Fatalf("ResolveHostRules: %v", err)
	}

	// Both v4 addresses admitted, sorted, in one add-element command; the v6 is not.
	if !strings.Contains(res.AddElements, "add element inet nullbox allow4 {") {
		t.Fatalf("missing add element: %q", res.AddElements)
	}
	for _, want := range []string{"203.0.113.10", "203.0.113.20"} {
		if !strings.Contains(res.AddElements, want) {
			t.Errorf("expected %s in add element, got %q", want, res.AddElements)
		}
	}
	if strings.Contains(res.AddElements, "2001:db8") {
		t.Errorf("IPv6 address must not be admitted to the ipv4 set: %q", res.AddElements)
	}

	// Three skipped: wildcard, ported, NXDOMAIN.
	if len(res.Skipped) != 3 {
		t.Fatalf("expected 3 skipped, got %d: %+v", len(res.Skipped), res.Skipped)
	}
	skipped := map[string]bool{}
	for _, s := range res.Skipped {
		skipped[s.Host] = true
	}
	for _, h := range []string{"*.staging.example.com", "admin.example.com", "gone.example.com"} {
		if !skipped[h] {
			t.Errorf("expected %s to be skipped", h)
		}
	}
}

// Integration: compile a manifest with a host target, then resolve it.
func TestCompileThenResolve(t *testing.T) {
	e := &model.Engagement{
		APIVersion: "nullbox/v1", Kind: "Engagement",
		Metadata: model.Metadata{Name: "acme", Authorization: model.Authorization{Ref: "SOW-1"}},
		Spec: model.Spec{
			Window:  model.Window{End: "2026-12-31T00:00:00Z"},
			Network: model.Network{Profile: model.ProfileNAT},
			Scope:   model.Scope{Allow: []model.Target{{Host: "app.example.com"}}},
		},
	}
	rs, err := CompileWith(e, Options{ResolverIP: "10.0.2.3"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// DNS restricted to the resolver, not open to the world.
	if !strings.Contains(rs.NFT, "ip daddr 10.0.2.3 udp dport 53 accept") {
		t.Errorf("expected DNS restricted to resolver, got:\n%s", rs.NFT)
	}
	if strings.Contains(rs.NFT, "\t\tudp dport 53 accept") {
		t.Errorf("expected no broad DNS accept when resolver is set")
	}
	res, err := ResolveHostRules(rs.UnresolvedHosts, fakeResolver(map[string][]string{"app.example.com": {"93.184.216.34"}}))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !strings.Contains(res.AddElements, "93.184.216.34") {
		t.Errorf("expected resolved app IP in add element, got %q", res.AddElements)
	}
}
