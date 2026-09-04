// Package contract generates the AI agent's environment contract — the
// ~/.claude/CLAUDE.md text — from the same Engagement manifest that
// policy.Compile turns into the nftables rules. policy renders the manifest to
// the ENFORCED egress rules; contract renders it to the DESCRIBED capabilities
// the agent reads at startup. Two views of one authorization record.
//
// Stdlib only, so it is offline/hardware-free testable like model and policy.
package contract

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

// Filename is the guest-relative path the contract is written to.
const Filename = ".claude/CLAUDE.md"

// Generate renders the environment contract for an engagement. Pure, no I/O.
// It does NOT call Validate — Up already validated, and tests build partials.
func Generate(e *model.Engagement) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("# nullbox engagement contract — %s", e.Metadata.Name)
	w("")
	if e.Metadata.Client != "" {
		w("Client: %s", e.Metadata.Client)
	}
	w("Authorization: %s", orNone(e.Metadata.Authorization.Ref))
	w("Window ends: %s — egress auto-expires then; finish or checkpoint before it.", e.Spec.Window.End)
	w("Profile: %s", e.Spec.Network.Profile)
	w("")
	w("This contract is DESCRIPTIVE. The real boundary is the nftables egress")
	w("policy, enforced by the host, not by you.")
	w("")

	writeGroundRules(w, e)
	writeProfileSection(w, e.Spec.Network.Profile)
	writeToolingSection(w, e.Spec.Network.Profile, e.Spec.Capabilities.InfraTools)
	writeScopeSection(w, e)
	return b.String()
}

func writeGroundRules(w func(string, ...any), e *model.Engagement) {
	w("## Ground rules")
	w("")
	w("- Egress is DENY-BY-DEFAULT. Only the in-scope destinations below are")
	w("  reachable; everything else is dropped at the host firewall.")
	w("- A blocked or timed-out connection is NOT evidence of a clean result. It")
	w("  is an environment artifact. NEVER close a coverage cell or mark a target")
	w("  secure on a dropped connection — record it as OUT-OF-SCOPE / not-tested")
	w("  and move on.")
	if e.Spec.Network.DenyMetadataEnabled() {
		w("- Cloud/instance metadata (169.254.169.254 + link-local) is BLOCKED and")
		w("  OUT OF SCOPE. Do not treat a metadata timeout as a finding.")
	} else {
		w("- Cloud/instance metadata (169.254.169.254) is REACHABLE here: an")
		w("  authorized IMDS test is IN SCOPE for this engagement (denyMetadata:false).")
	}
	w("- Established/return traffic and loopback pass. DNS is open only when the")
	w("  scope names host targets to resolve.")
	w("")
}

func writeProfileSection(w func(string, ...any), p model.Profile) {
	w("## Network profile: %s", p)
	w("")
	switch p {
	case model.ProfileNAT:
		w("WORKS: nmap -sT, curl and any TCP client; UDP to in-scope hosts and ICMP")
		w("  echo (ping). Good for /web-exploit, /api-security, /ssl-tls-audit,")
		w("  /oauth-security, /codebase.")
		w("BLOCKED: raw sockets — SYN/half-open (nmap -sS), ACK/FIN/Xmas, hping3,")
		w("  scapy (user-mode NAT presents sockets, not a TAP — use nmap -sT);")
		w("  arp-scan, Responder, mitm6 (no broadcast segment).")
		w("A blocked raw-socket technique here is a PROFILE limit, not a target result.")
	case model.ProfileRouted:
		w("WORKS: full L3/L4 raw to the in-scope CIDRs — nmap -sS/-sU/-sA/-sX, ICMP")
		w("  sweeps, masscan, hping3, raw UDP probes.")
		w("BLOCKED: L2/broadcast tools — arp-scan, Responder (LLMNR/NBT-NS/mDNS),")
		w("  mitm6. On a ROUTED tap you are one hop from the target — you are")
		w("  NOT on their broadcast domain. Use the l2 profile for those; anything")
		w("  outside the scoped CIDRs is dropped.")
	case model.ProfileL2:
		w("WORKS: everything routed gives, PLUS live broadcast-domain attacks on the")
		w("  segment this host sits on — arp-scan/ARP spoofing, Responder")
		w("  (LLMNR/NBT-NS/mDNS), mitm6 (DHCPv6/rogue RA), netexec sweeps.")
		w("NOTE: placement-bound. Only THIS host's broadcast domain is L2-reachable;")
		w("  in-scope CIDRs elsewhere stay routed and scope-filtered.")
	default:
		w("WORKS: as configured. BLOCKED: anything outside the scoped destinations.")
	}
	w("")
}

func writeToolingSection(w func(string, ...any), p model.Profile, infra bool) {
	w("## Toolset")
	w("")
	if infra {
		w("FULL image: web + infra tools present (masscan, netexec, responder,")
		w("  arp-scan, impacket, hydra…).")
		if p == model.ProfileNAT {
			w("Note: the infra tools are of limited use on the nat profile (no raw/L2).")
		}
	} else {
		w("THIN image: web + codebase tools only. The infra tools (masscan, netexec,")
		w("  responder, arp-scan…) are ABSENT in the thin image.")
		if p == model.ProfileRouted || p == model.ProfileL2 {
			w("Note: this %s profile can carry raw/L2 traffic, but those tools are", p)
			w("  absent in the thin image — rebuild with --with-infra to use them.")
		}
	}
	w("")
}

func writeScopeSection(w func(string, ...any), e *model.Engagement) {
	w("## Scope (the authorization record)")
	w("")
	w("Allowed:")
	if len(e.Spec.Scope.Allow) == 0 {
		w("- (none)")
	}
	for _, t := range e.Spec.Scope.Allow {
		w("- %s", targetLine(t))
	}
	w("")
	w("Denied (deny wins over any allow above):")
	if len(e.Spec.Scope.Deny) == 0 {
		w("- (none)")
	}
	for _, t := range e.Spec.Scope.Deny {
		w("- %s", denyLine(t))
	}
	w("")
}

func targetLine(t model.Target) string {
	if t.Host != "" {
		if strings.HasPrefix(t.Host, "*.") {
			return t.Host + " (wildcard host, SNI-scoped)"
		}
		return t.Host + " (host, resolved at apply time)"
	}
	if len(t.Ports) == 0 {
		return t.CIDR + " (all ports)"
	}
	return fmt.Sprintf("%s (tcp/udp %s)", t.CIDR, joinPorts(t.Ports))
}

// denyLine renders a deny target. A CIDR deny drops the whole prefix (deny wins).
// A host-form deny is NOT enforceable at the packet filter — the compiler
// rejects it — so the contract must not claim it is blocked.
func denyLine(t model.Target) string {
	if t.CIDR != "" {
		return t.CIDR + " (whole prefix dropped — deny wins over any allow)"
	}
	return t.Host + " (host deny — NOT enforceable at the packet filter; express it as a CIDR)"
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// WriteInto materializes the contract at <guestHome>/.claude/CLAUDE.md and
// returns the path. The driver's booter calls this while staging the guest.
func WriteInto(guestHome string, e *model.Engagement) (string, error) {
	dir := filepath.Join(guestHome, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "CLAUDE.md")
	if err := os.WriteFile(path, []byte(Generate(e)), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
