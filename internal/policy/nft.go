// Package policy compiles an Engagement manifest into an nftables ruleset.
//
// This is the architectural core of nullbox. Scope is enforced at a stateful
// PACKET FILTER on the microVM's egress path, so the full toolchain (nmap -sS,
// UDP scans, ping sweeps, arp-scan) passes while scope stays deny-by-default and
// CIDR/host-scoped.
//
// Two enforcement points share ONE filter body (writeFilterBody):
//   - the `egress` chain on the netfilter `output` hook — filters the HOST's own
//     processes (host self-protection);
//   - when Options.EgressIface is set, a `forward` hook chain jumps guest traffic
//     arriving on the microVM's TAP to a `guest_egress` chain carrying the same
//     body, plus a `postrouting` masquerade so the guest can reach routable
//     targets. The `output` hook is NOT traversed by forwarded guest packets, so
//     without the forward chain a routed guest would be entirely unfiltered.
//
// Accept and drop rules also mirror to nfnetlink_log (NFLOGGroupAccept/Drop) via
// separate, non-terminating `log ... group N` rules, so a console.Feed reader can
// stream allowed vs dropped egress as evidence.
//
// The compiler is stdlib + internal/model only, so it is unit-tested on any
// machine with no nft binary. Rendering is pure text; applying it (nft -f) is the
// driver's job on a Linux host.
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

	// NFLOGGroupAccept / NFLOGGroupDrop are the nfnetlink_log groups the accept
	// and drop rules mirror to. The console.Feed reader binds the same numbers.
	NFLOGGroupAccept = 331
	NFLOGGroupDrop   = 332
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
	// address instead of allowing 53 to any destination.
	ResolverIP string
	// EgressIface, when set (the guest's TAP name), makes the compiler also emit
	// a `forward` hook chain + `guest_egress` filter + `postrouting` masquerade
	// so guest egress across that interface is filtered and NAT'd. Only the
	// firecracker driver, which knows the tap, sets this — the render path and
	// tests keep it empty.
	EgressIface string
	// UplinkIface is the masquerade output interface. Empty => masquerade on any
	// interface that is not the tap.
	UplinkIface string
	// EnableForward is implied by EgressIface != "" and kept for clarity at call
	// sites; the forward/nat chains are emitted when EgressIface != "".
	EnableForward bool
}

func (o Options) forwardEnabled() bool { return o.EgressIface != "" }

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
	// Fail closed: a host-form deny cannot be enforced at the packet filter (it
	// would be silently ignored while the contract claims it is blocked). Reject
	// it so scope stays honest.
	if len(deny.hosts) > 0 {
		return nil, fmt.Errorf("deny: host-form deny target %q is not enforceable at the packet filter; express the block as a CIDR", deny.hosts[0].Host)
	}
	denyMeta := e.Spec.Network.DenyMetadataEnabled()

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("#!/usr/sbin/nft -f")
	w("# nullbox egress policy — generated from engagement %q (auth: %s)",
		e.Metadata.Name, e.Metadata.Authorization.Ref)
	w("# window ends: %s   profile: %s", e.Spec.Window.End, e.Spec.Network.Profile)
	w("# deny-by-default. deny always wins over allow. do not hand-edit.")
	w("")
	w("table inet %s", tableName)
	w("delete table inet %s", tableName)
	if opts.forwardEnabled() {
		w("table ip %s", tableName)
		w("delete table ip %s", tableName)
	}
	w("table inet %s {", tableName)

	// A named interval set for allowed IPv4 prefixes that permit ALL ports.
	// auto-merge folds overlapping/nested prefixes (e.g. 10.0.0.0/8 + a /32 jump
	// host inside it) instead of letting nft reject the whole ruleset.
	w("\tset %s {", allowSet4Name)
	w("\t\ttype ipv4_addr")
	w("\t\tflags interval")
	w("\t\tauto-merge")
	if elems := renderPrefixSet(allow.unportedCIDRs); elems != "" {
		w("\t\telements = { %s }", elems)
	}
	w("\t}")
	w("")

	// The host self-protection chain (output hook). Body shared with guest_egress.
	w("\tchain %s {", chainEgress)
	w("\t\ttype filter hook output priority 0; policy drop;")
	w("")
	w("\t\t# established/related and loopback always pass")
	w("\t\tct state established,related accept")
	w("\t\toif \"lo\" accept")
	w("")
	writeFilterBody(w, allow, deny, denyMeta, opts.ResolverIP)
	w("\t}")

	// Guest egress path — only when a TAP is known (the firecracker routed/l2
	// driver). The output hook never sees forwarded guest packets, so this is
	// where the guest is actually filtered.
	if opts.forwardEnabled() {
		tap := opts.EgressIface
		w("")
		w("\tchain forward {")
		w("\t\ttype filter hook forward priority 0; policy accept;")
		w("\t\tct state established,related accept")
		w("\t\toifname \"%s\" accept", tap) // return traffic to the guest
		w("\t\tiifname \"%s\" jump guest_egress", tap)
		w("\t}")
		w("")
		// guest_egress is a regular (no-hook) chain; deny-by-default for the guest
		// is its terminal `counter drop`, NOT a drop-policy hook (which would break
		// every other forwarded flow on the host).
		w("\tchain guest_egress {")
		writeFilterBody(w, allow, deny, denyMeta, opts.ResolverIP)
		w("\t}")
	}

	w("}")

	// Masquerade lives in a SEPARATE ip-family table: NAT chains in the inet
	// family need kernel >= 5.2, but Firecracker supports older kernels, so an
	// inet nat chain would make the whole load fail there. flushNFT deletes both
	// tables.
	if opts.forwardEnabled() {
		tap := opts.EgressIface
		uplinkMatch := "oifname != \"" + tap + "\""
		if opts.UplinkIface != "" {
			uplinkMatch = "oifname \"" + opts.UplinkIface + "\""
		}
		w("")
		w("table ip %s {", tableName)
		w("\tchain postrouting {")
		w("\t\ttype nat hook postrouting priority srcnat; policy accept;")
		w("\t\tiifname \"%s\" %s masquerade", tap, uplinkMatch)
		w("\t}")
		w("}")
	}

	rs := &Ruleset{NFT: b.String()}
	rs.UnresolvedHosts = append(rs.UnresolvedHosts, allow.hosts...)
	return rs, nil
}

// writeFilterBody emits the shared deny/allow body: metadata + explicit-deny
// drops, DNS, ported and all-ports accepts, and the logged catch-all drop.
// Accept and drop each get a separate, non-terminating `log ... group N` rule
// BEFORE the verdict, so the verdict lines stay byte-identical (and testable)
// while every decision is mirrored to nfnetlink_log.
func writeFilterBody(w func(string, ...any), allow, deny partitioned, denyMeta bool, resolverIP string) {
	logAccept := func(match, note string) {
		w("\t\t%s log prefix \"nullbox-allow %s\" group %d", match, note, NFLOGGroupAccept)
	}
	logDrop := func(match, note string) {
		w("\t\t%s log prefix \"nullbox-drop %s\" group %d", match, note, NFLOGGroupDrop)
	}

	if denyMeta {
		w("\t\t# instance/cloud metadata — always denied (agent must not reach host creds)")
		logDrop("ip daddr "+metadataV4, "meta ")
		w("\t\tip daddr %s drop", metadataV4)
		logDrop("ip daddr "+linkLocalV4, "meta ")
		w("\t\tip daddr %s drop", linkLocalV4)
		w("")
	}
	if len(deny.unportedCIDRs) > 0 || len(deny.portedCIDRs) > 0 {
		w("\t\t# explicit scope carve-outs (deny wins)")
		for _, p := range append(append([]netip.Prefix{}, deny.unportedCIDRs...), portedPrefixes(deny.portedCIDRs)...) {
			logDrop("ip daddr "+p.String(), "deny ")
			w("\t\tip daddr %s drop", p.String())
		}
		w("")
	}

	if len(allow.hosts) > 0 {
		w("\t\t# DNS needed to resolve host-form scope entries")
		if resolverIP != "" {
			logAccept("ip daddr "+resolverIP+" udp dport 53", "dns ")
			w("\t\tip daddr %s udp dport 53 accept", resolverIP)
			logAccept("ip daddr "+resolverIP+" tcp dport 53", "dns ")
			w("\t\tip daddr %s tcp dport 53 accept", resolverIP)
		} else {
			logAccept("udp dport 53", "dns ")
			w("\t\tudp dport 53 accept")
			logAccept("tcp dport 53", "dns ")
			w("\t\ttcp dport 53 accept")
		}
		w("")
	}

	w("\t\t# in-scope destinations")
	for _, pc := range allow.portedCIDRs {
		set := joinPorts(pc.ports)
		logAccept(fmt.Sprintf("ip daddr %s tcp dport { %s }", pc.prefix.String(), set), "")
		w("\t\tip daddr %s tcp dport { %s } accept", pc.prefix.String(), set)
		logAccept(fmt.Sprintf("ip daddr %s udp dport { %s }", pc.prefix.String(), set), "")
		w("\t\tip daddr %s udp dport { %s } accept", pc.prefix.String(), set)
	}
	logAccept("ip daddr @"+allowSet4Name, "")
	w("\t\tip daddr @%s accept", allowSet4Name)
	w("")
	w("\t\t# everything else: logged then dropped")
	w("\t\tlog prefix \"nullbox-drop \" group %d", NFLOGGroupDrop)
	w("\t\tcounter drop")
}

// portedCIDR is a prefix restricted to a set of ports.
type portedCIDR struct {
	prefix netip.Prefix
	ports  []int
}

// partitioned is the normalized, split form of a scope list.
type partitioned struct {
	unportedCIDRs []netip.Prefix
	portedCIDRs   []portedCIDR
	hosts         []HostRule
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
// interval set. Only IPv4 prefixes are emitted (v6 is a phase-1 addition).
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
