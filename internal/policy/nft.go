// Package policy compiles an Engagement manifest into an nftables ruleset.
//
// This is the architectural core of nullbox and the one thing that makes it
// different from sbx. sbx enforces scope at an L7/L4 proxy that terminates TCP,
// which is precisely why UDP, ICMP, raw sockets and L2 die inside it. nullbox
// enforces at a stateful PACKET FILTER on the microVM's egress path, so the
// full toolchain (nmap -sS, UDP scans, ping sweeps, arp-scan) passes while
// scope stays deny-by-default and CIDR/host-scoped.
//
// The compiler is deliberately dependency-free (stdlib + internal/model) so it
// can be unit tested with `go test ./internal/policy/...` on any machine, with
// no external modules and no nft binary present. Rendering a ruleset is pure
// text; APPLYING it (nft -f) is the driver's job on a Linux host.
//
// Scope semantics enforced here:
//   - deny-by-default (chain policy drop, plus a logged catch-all)
//   - deny always wins (metadata + explicit deny CIDRs are dropped first)
//   - a CIDR target with no ports => all ports allowed (via the @allow4 set)
//   - a CIDR target WITH ports => only those ports allowed; it is NOT also
//     swept into @allow4, so the port restriction actually holds
//   - host (FQDN) targets need runtime DNS resolution and are returned in
//     UnresolvedHosts for the driver's resolver step (phase 1); DNS/53 is only
//     opened when there is at least one host target to resolve.
package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

const (
	metadataV4    = "169.254.169.254"
	linkLocalV4   = "169.254.0.0/16"
	tableName     = "nullbox"
	chainEgress   = "egress"
	allowSet4Name = "allow4"
)

// TableName is the nftables table the compiled ruleset installs. Exported so a
// driver can flush it (the kill switch) without hardcoding the string.
const TableName = tableName

// Ruleset is a rendered nftables program plus the metadata a driver needs to
// finish the job (which host targets still require DNS resolution).
type Ruleset struct {
	NFT             string     // the full `nft -f` program
	UnresolvedHosts []HostRule // host targets to resolve at apply time
}

// HostRule is a scope entry expressed as an FQDN (optionally port-scoped),
// pending DNS resolution before it can become a concrete accept rule.
type HostRule struct {
	Host  string
	Ports []int
}

// Options tunes compilation.
type Options struct {
	// ResolverIP, when set, restricts DNS (port 53) to that single resolver
	// address instead of allowing 53 to any destination. Set by a driver once
	// it knows the guest's resolver, closing a DNS-exfil path. Empty keeps the
	// broad phase-0 behavior.
	ResolverIP string
}

// Compile turns an engagement into a ruleset with default options.
func Compile(e *model.Engagement) (*Ruleset, error) {
	return CompileWith(e, Options{})
}

// CompileWith turns an engagement into a ruleset. It errors only on genuinely
// malformed input that slipped past model.Validate (defense in depth).
func CompileWith(e *model.Engagement, opts Options) (*Ruleset, error) {
	allow, err := partition(e.Spec.Scope.Allow)
	if err != nil {
		return nil, fmt.Errorf("allow: %w", err)
	}
	deny, err := partition(e.Spec.Scope.Deny)
	if err != nil {
		return nil, fmt.Errorf("deny: %w", err)
	}

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("#!/usr/sbin/nft -f")
	w("# nullbox egress policy — generated from engagement %q (auth: %s)",
		e.Metadata.Name, e.Metadata.Authorization.Ref)
	w("# window ends: %s   profile: %s", e.Spec.Window.End, e.Spec.Network.Profile)
	w("# deny-by-default. deny always wins over allow. do not hand-edit.")
	w("")
	// Idempotent apply: replace the whole table each time.
	w("table inet %s", tableName)
	w("delete table inet %s", tableName)
	w("table inet %s {", tableName)

	// A named interval set for allowed IPv4 prefixes that permit ALL ports.
	// Port-scoped prefixes are handled by explicit rules instead and are kept
	// OUT of this set so their restriction holds.
	w("\tset %s {", allowSet4Name)
	w("\t\ttype ipv4_addr")
	w("\t\tflags interval")
	if elems := renderPrefixSet(allow.unportedCIDRs); elems != "" {
		w("\t\telements = { %s }", elems)
	}
	w("\t}")
	w("")

	w("\tchain %s {", chainEgress)
	w("\t\ttype filter hook output priority 0; policy drop;")
	w("")
	w("\t\t# established/related and loopback always pass")
	w("\t\tct state established,related accept")
	w("\t\toif \"lo\" accept")
	w("")

	// Denies first — they win over any allow below.
	if e.Spec.Network.DenyMetadataEnabled() {
		w("\t\t# instance/cloud metadata — always denied (agent must not reach host creds)")
		w("\t\tip daddr %s drop", metadataV4)
		w("\t\tip daddr %s drop", linkLocalV4)
		w("")
	}
	if len(deny.unportedCIDRs) > 0 || len(deny.portedCIDRs) > 0 {
		// A deny is coarse and safe: drop the whole prefix regardless of any
		// ports on the deny entry. Deny wins, so over-blocking is the correct
		// failure direction.
		w("\t\t# explicit scope carve-outs (deny wins)")
		for _, p := range append(append([]netip.Prefix{}, deny.unportedCIDRs...), portedPrefixes(deny.portedCIDRs)...) {
			w("\t\tip daddr %s drop", p.String())
		}
		w("")
	}

	if len(allow.hosts) > 0 {
		w("\t\t# DNS needed to resolve host-form scope entries")
		if opts.ResolverIP != "" {
			w("\t\tip daddr %s udp dport 53 accept", opts.ResolverIP)
			w("\t\tip daddr %s tcp dport 53 accept", opts.ResolverIP)
		} else {
			w("\t\tudp dport 53 accept")
			w("\t\ttcp dport 53 accept")
		}
		w("")
	}

	w("\t\t# in-scope destinations")
	// Port-scoped prefixes: only the named ports, for tcp and udp.
	for _, pc := range allow.portedCIDRs {
		set := joinPorts(pc.ports)
		w("\t\tip daddr %s tcp dport { %s } accept", pc.prefix.String(), set)
		w("\t\tip daddr %s udp dport { %s } accept", pc.prefix.String(), set)
	}
	// Unported prefixes: all ports, all L4 protocols (incl. icmp/raw) — the set.
	w("\t\tip daddr @%s accept", allowSet4Name)
	w("")
	w("\t\t# everything else: logged then dropped (policy drop is the backstop)")
	w("\t\tlog prefix \"nullbox-drop \" level info")
	w("\t\tcounter drop")
	w("\t}")
	w("}")

	rs := &Ruleset{NFT: b.String()}
	for _, h := range allow.hosts {
		rs.UnresolvedHosts = append(rs.UnresolvedHosts, h)
	}
	return rs, nil
}

// portedCIDR is a prefix restricted to a set of ports.
type portedCIDR struct {
	prefix netip.Prefix
	ports  []int
}

// partitioned is the normalized, split form of a scope list.
type partitioned struct {
	unportedCIDRs []netip.Prefix // all-ports prefixes
	portedCIDRs   []portedCIDR   // port-restricted prefixes
	hosts         []HostRule     // FQDN targets, pending resolution
}

func partition(ts []model.Target) (partitioned, error) {
	var p partitioned
	for _, t := range ts {
		switch {
		case t.CIDR != "":
			pref, err := netip.ParsePrefix(t.CIDR)
			if err != nil {
				return partitioned{}, fmt.Errorf("cidr %q: %w", t.CIDR, err)
			}
			pref = pref.Masked()
			if len(t.Ports) == 0 {
				p.unportedCIDRs = append(p.unportedCIDRs, pref)
			} else {
				p.portedCIDRs = append(p.portedCIDRs, portedCIDR{prefix: pref, ports: dedupeSortPorts(t.Ports)})
			}
		case t.Host != "":
			p.hosts = append(p.hosts, HostRule{Host: t.Host, Ports: dedupeSortPorts(t.Ports)})
		default:
			return partitioned{}, fmt.Errorf("target has neither cidr nor host")
		}
	}
	return p, nil
}

func portedPrefixes(pcs []portedCIDR) []netip.Prefix {
	out := make([]netip.Prefix, len(pcs))
	for i, pc := range pcs {
		out[i] = pc.prefix
	}
	return out
}

// renderPrefixSet returns a sorted, de-duplicated element list for an nftables
// interval set. Only IPv4 prefixes are emitted (v6 is a phase-1 addition); v6
// prefixes are skipped rather than mis-rendered.
func renderPrefixSet(prefixes []netip.Prefix) string {
	seen := map[string]bool{}
	var out []string
	for _, p := range prefixes {
		if !p.Addr().Is4() {
			continue
		}
		s := p.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func joinPorts(ports []int) string {
	list := make([]string, len(ports))
	for i, p := range ports {
		list[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(list, ", ")
}

func dedupeSortPorts(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}
