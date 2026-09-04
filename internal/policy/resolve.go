package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Resolver maps a hostname to its addresses. Injected so ResolveHostRules is
// testable without DNS; a driver passes a net.LookupHost-backed implementation.
type Resolver func(host string) ([]netip.Addr, error)

// Resolution is the outcome of resolving the host-form scope entries into
// concrete nftables commands applied on top of the base ruleset.
type Resolution struct {
	// AddElements is an `nft` program (add element commands) that adds the
	// resolved IPv4 addresses to the base ruleset's allow4 set. Set membership
	// is order-independent, so this is safe to apply after the base table.
	AddElements string
	// Skipped lists host entries that could not be turned into a static rule:
	// wildcards (need SNI/DNS sniffing, phase 2) and port-scoped hosts (phase
	// 2). The caller should surface these so they are not mistaken for allowed.
	Skipped []SkippedHost
	// Resolved maps each concrete host to the addresses it contributed.
	Resolved map[string][]netip.Addr
}

// SkippedHost records a host entry that was not statically resolvable and why.
type SkippedHost struct {
	Host   string
	Reason string
}

// ResolveHostRules resolves the all-ports, non-wildcard host targets to IPv4
// addresses and renders the `add element` program that admits them. Wildcards
// and port-scoped hosts are returned in Skipped rather than silently allowed.
func ResolveHostRules(hosts []HostRule, resolve Resolver) (*Resolution, error) {
	res := &Resolution{Resolved: map[string][]netip.Addr{}}
	seen := map[string]bool{}
	var addrs []string

	for _, h := range hosts {
		switch {
		case strings.HasPrefix(h.Host, "*."):
			res.Skipped = append(res.Skipped, SkippedHost{h.Host, "wildcard needs SNI/DNS sniffing (phase 2)"})
			continue
		case len(h.Ports) > 0:
			res.Skipped = append(res.Skipped, SkippedHost{h.Host, "port-scoped host resolution (phase 2)"})
			continue
		}
		got, err := resolve(h.Host)
		if err != nil {
			res.Skipped = append(res.Skipped, SkippedHost{h.Host, fmt.Sprintf("resolve failed: %v", err)})
			continue
		}
		var v4 []netip.Addr
		for _, a := range got {
			if !a.Is4() {
				continue // IPv6 is phase 2 (allow4 is an ipv4 set)
			}
			v4 = append(v4, a)
			if s := a.String(); !seen[s] {
				seen[s] = true
				addrs = append(addrs, s)
			}
		}
		if len(v4) == 0 {
			res.Skipped = append(res.Skipped, SkippedHost{h.Host, "no IPv4 address resolved"})
			continue
		}
		res.Resolved[h.Host] = v4
	}

	if len(addrs) > 0 {
		sort.Strings(addrs)
		res.AddElements = fmt.Sprintf("add element inet %s %s { %s }\n",
			tableName, allowSet4Name, strings.Join(addrs, ", "))
	}
	return res, nil
}
