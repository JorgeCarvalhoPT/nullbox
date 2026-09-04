//go:build linux

package driver

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/policy"
)

// (registration lives in firecracker_boot_linux.go, which wires the real booter.)

// fcDriver runs an engagement as a Firecracker microVM on Linux. The
// security-critical pieces — applying the deny-by-default egress ruleset,
// resolving host-form scope entries into it, and the kill switch — are
// implemented here for real. The microVM boot itself is pluggable via `boot`
// so this package does not hardcode a jailer/config that cannot be verified in
// CI; wire a booter to complete `up`.
//
// NOTE (phase 1 limitation): the nftables table name is fixed (policy.TableName),
// so one routed/l2 engagement is active per host at a time. Multi-engagement on
// one host needs per-engagement table names; the cluster (kata) path sidesteps
// this with a namespace per engagement.
type fcDriver struct {
	boot bootFunc // nil until wired; keeps Up from mutating host state it cannot finish
}

// bootFunc boots the microVM for spec on the prepared tap device and returns
// its status. Applying egress policy has already happened when it is called.
type bootFunc func(spec UpSpec, tap string) (*Status, error)

func (*fcDriver) Name() model.Driver { return model.DriverFirecracker }

func (*fcDriver) Preflight(profile model.Profile) error {
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return fmt.Errorf("/dev/kvm not present — Firecracker needs KVM (bare metal or a nested-virt instance): %w", err)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft (nftables) not found in PATH — required to apply the egress policy")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("iproute2 `ip` not found in PATH — required for TAP setup")
	}
	switch profile {
	case model.ProfileRouted, model.ProfileL2, model.ProfileNAT:
		return nil
	default:
		return fmt.Errorf("unknown profile %q", profile)
	}
}

func (d *fcDriver) Up(spec UpSpec) (*Status, error) {
	if err := d.Preflight(spec.Engagement.Spec.Network.Profile); err != nil {
		return nil, err
	}
	if d.boot == nil {
		// Do not touch host state we cannot finish. Everything below this line
		// is real; it runs once a booter is provided.
		return nil, fmt.Errorf("firecracker: egress policy, host resolution and the " +
			"kill switch are implemented, but the microVM boot is not wired in this " +
			"build. Provide a bootFunc (firecracker config + jailer) to complete `up`")
	}

	// 1. Prepare the TAP (with its /30 gateway) and enable forwarding, so the
	//    guest can route out through the host.
	tap := "nbx-" + spec.Engagement.Metadata.Name
	if err := ensureTAP(tap); err != nil {
		delTAP(tap) // don't leave a half-created interface for the next run to reuse
		return nil, fmt.Errorf("tap setup: %w", err)
	}
	if err := ensureIPForward(); err != nil {
		delTAP(tap)
		return nil, fmt.Errorf("enable ip_forward: %w", err)
	}
	uplink := defaultUplink()

	// 2. Recompile the ruleset now that the tap + uplink are known, so the
	//    forward-hook + masquerade chains carry the real interface names.
	//    (spec.Ruleset was compiled host-agnostically; the output-hook chain it
	//    contains does NOT see forwarded guest traffic — this is the real filter.)
	rs, err := policy.CompileWith(spec.Engagement, policy.Options{
		EgressIface: tap, UplinkIface: uplink, EnableForward: true,
	})
	if err != nil {
		delTAP(tap)
		return nil, fmt.Errorf("compile forward policy: %w", err)
	}
	if err := applyNFT(rs.NFT); err != nil {
		delTAP(tap)
		return nil, fmt.Errorf("apply egress policy: %w", err)
	}

	// 3. Resolve host-form scope entries and admit them to the allow set.
	if len(rs.UnresolvedHosts) > 0 {
		res, err := policy.ResolveHostRules(rs.UnresolvedHosts, systemResolver)
		if err != nil {
			flushNFT()
			delTAP(tap)
			return nil, fmt.Errorf("resolve host scope: %w", err)
		}
		for _, s := range res.Skipped {
			fmt.Fprintf(os.Stderr, "nullbox: host %q not admitted (%s)\n", s.Host, s.Reason)
		}
		if res.AddElements != "" {
			if err := applyNFT(res.AddElements); err != nil {
				flushNFT()
				delTAP(tap)
				return nil, fmt.Errorf("admit resolved hosts: %w", err)
			}
		}
	}

	// 4. Boot the microVM.
	st, err := d.boot(spec, tap)
	if err != nil {
		delTAP(tap)
		flushNFT()
		return nil, fmt.Errorf("boot microVM: %w", err)
	}
	return st, nil
}

func (*fcDriver) Shell(name string) error {
	return fmt.Errorf("firecracker: shell requires a booted microVM (VM console/exec is wired with the booter) — engagement %q", name)
}

// Kill is the panic button. It severs the guest's egress PATH first (delete the
// TAP) THEN flushes the ruleset — deleting the deny-by-default table alone would
// leave the forward hook default-accept with ip_forward still on, i.e. fail
// OPEN. Safe to call repeatedly and without a healthy VM.
func (*fcDriver) Kill(name string) error {
	delTAP("nbx-" + name)
	if err := flushNFT(); err != nil {
		return fmt.Errorf("flush egress policy for %q: %w", name, err)
	}
	return nil
}

func (d *fcDriver) Down(name string) error {
	delTAP("nbx-" + name)
	return d.Kill(name)
}

func (*fcDriver) List() ([]Status, error) { return nil, nil }

// ---- real helpers -------------------------------------------------------

func applyNFT(program string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(program)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// flushNFT removes both nullbox tables: the inet filter table and the ip NAT
// table (present only when a routed guest was up). Absence is success.
func flushNFT() error {
	del := func(fam string) error {
		out, err := exec.Command("nft", "delete", "table", fam, policy.TableName).CombinedOutput()
		if err != nil {
			s := string(out)
			if strings.Contains(s, "No such file") || strings.Contains(s, "does not exist") {
				return nil
			}
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(s))
		}
		return nil
	}
	if err := del("inet"); err != nil {
		return err
	}
	return del("ip")
}

func ensureTAP(tap string) error {
	// Create only if missing, but ALWAYS (re)assert the /30 gateway and up state
	// so a leftover addressless/down TAP from a partial prior run is corrected
	// rather than silently reused (which would boot the guest with a nonexistent
	// gateway).
	if _, err := net.InterfaceByName(tap); err != nil {
		if out, err := exec.Command("ip", "tuntap", "add", "dev", tap, "mode", "tap").CombinedOutput(); err != nil {
			return fmt.Errorf("ip tuntap add: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	// The host TAP is the guest's default gateway (fcHostTapIP/30).
	if out, err := exec.Command("ip", "addr", "add", fcTapCIDR, "dev", tap).CombinedOutput(); err != nil {
		if s := strings.TrimSpace(string(out)); !strings.Contains(s, "File exists") {
			return fmt.Errorf("ip addr add: %v: %s", err, s)
		}
	}
	if out, err := exec.Command("ip", "link", "set", tap, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func delTAP(tap string) {
	_ = exec.Command("ip", "link", "del", tap).Run() // best effort
}

func systemResolver(host string) ([]netip.Addr, error) {
	names, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, s := range names {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}
