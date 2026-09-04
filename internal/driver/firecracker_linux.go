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

func init() { register(&fcDriver{}) }

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

	// 1. Apply the deny-by-default base ruleset.
	if err := applyNFT(spec.Ruleset.NFT); err != nil {
		return nil, fmt.Errorf("apply egress policy: %w", err)
	}
	// 2. Resolve host-form scope entries and admit them to the allow set.
	if len(spec.Ruleset.UnresolvedHosts) > 0 {
		res, err := policy.ResolveHostRules(spec.Ruleset.UnresolvedHosts, systemResolver)
		if err != nil {
			flushNFT() // roll back: never leave a half-open policy
			return nil, fmt.Errorf("resolve host scope: %w", err)
		}
		for _, s := range res.Skipped {
			fmt.Fprintf(os.Stderr, "nullbox: host %q not admitted (%s)\n", s.Host, s.Reason)
		}
		if res.AddElements != "" {
			if err := applyNFT(res.AddElements); err != nil {
				flushNFT()
				return nil, fmt.Errorf("admit resolved hosts: %w", err)
			}
		}
	}
	// 3. Prepare the TAP and boot.
	tap := "nbx-" + spec.Engagement.Metadata.Name
	if err := ensureTAP(tap); err != nil {
		flushNFT()
		return nil, fmt.Errorf("tap setup: %w", err)
	}
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

// Kill is the panic button: flush the egress ruleset immediately. It does not
// require a healthy VM and is safe to call repeatedly.
func (*fcDriver) Kill(name string) error {
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

// flushNFT removes the egress table. Absence is success (idempotent).
func flushNFT() error {
	cmd := exec.Command("nft", "delete", "table", "inet", policy.TableName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "No such file") || strings.Contains(string(out), "does not exist") {
			return nil
		}
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureTAP(tap string) error {
	// Idempotent: if it exists, reuse it.
	if _, err := net.InterfaceByName(tap); err == nil {
		return nil
	}
	if out, err := exec.Command("ip", "tuntap", "add", "dev", tap, "mode", "tap").CombinedOutput(); err != nil {
		return fmt.Errorf("ip tuntap add: %v: %s", err, strings.TrimSpace(string(out)))
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
