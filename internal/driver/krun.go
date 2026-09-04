package driver

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

func init() {
	register(&krunDriver{})
	// clh and kata are declared everywhere as stubs so the CLI can name them
	// and Preflight explains what they need. firecracker is registered per
	// platform: a real driver on Linux (firecracker_linux.go), a stub elsewhere
	// (firecracker_other.go).
	register(&stubDriver{name: model.DriverCLH, needs: "a Linux host with KVM + Cloud Hypervisor"})
	register(&stubDriver{name: model.DriverKata, needs: "a Kubernetes cluster with the sandboxed-containers (Kata) runtime"})
}

// defaultDriver picks a backend when the manifest does not pin one.
//
//   - nat    -> krun everywhere (user-mode networking, macOS + Linux)
//   - routed -> firecracker on Linux (TAP + nftables); krun cannot do raw/L2
//   - l2     -> firecracker on Linux (bridged TAP)
//
// On a non-Linux host the routed/l2 defaults still resolve to firecracker so
// Preflight can emit the precise "run this on a Linux host" message.
func defaultDriver(p model.Profile) model.Driver {
	switch p {
	case model.ProfileRouted, model.ProfileL2:
		return model.DriverFirecracker
	default:
		return model.DriverKrun
	}
}

// ---------------------------------------------------------------------------
// krun — laptop driver over libkrun/krunvm. Boots the Smith OCI image as a
// microVM on macOS (HVF) and Linux (KVM). Phase 0 implements Preflight fully;
// the lifecycle steps are the documented command plan a Linux/macOS host with
// libkrun completes.
// ---------------------------------------------------------------------------

type krunDriver struct{}

func (*krunDriver) Name() model.Driver { return model.DriverKrun }

func (*krunDriver) Preflight(profile model.Profile) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return fmt.Errorf("krun driver supports macOS and Linux only, not %s", runtime.GOOS)
	}
	if _, err := exec.LookPath("krunvm"); err != nil {
		return errors.New("krunvm not found in PATH — install libkrun + krunvm " +
			"(macOS: `brew install krunvm`; Linux: build from github.com/containers/krunvm)")
	}
	switch profile {
	case model.ProfileNAT:
		return nil
	case model.ProfileRouted, model.ProfileL2:
		// libkrun's networking is user-mode (passt/TSI). Full raw sockets / L2
		// need a TAP/bridge the krun path does not provide — use the
		// firecracker driver on a Linux host placed on the target segment.
		return fmt.Errorf("profile %q needs raw-socket/L2 networking which the krun "+
			"(user-mode) path cannot provide; use driver: firecracker on a Linux host", profile)
	default:
		return fmt.Errorf("unknown profile %q", profile)
	}
}

func (d *krunDriver) Up(spec UpSpec) (*Status, error) {
	if err := d.Preflight(spec.Engagement.Spec.Network.Profile); err != nil {
		return nil, err
	}
	// The command plan a libkrun host runs (phase 0 boundary — wired in phase 1
	// against a real host, where each step can actually be verified):
	//   1. buildah/krunvm create --cpus N --mem M --name <name> <ImageRef>
	//   2. configure passt/gvproxy allow-list from spec.Ruleset (nat scope)
	//   3. krunvm start <name>  (guest init = the ported smith-entrypoint)
	//   4. publish the dashboard port
	return nil, hostTODO("krun", "Up", spec.Engagement.Metadata.Name)
}

func (d *krunDriver) Shell(name string) error { return hostTODO("krun", "Shell", name) }
func (d *krunDriver) Kill(name string) error  { return hostTODO("krun", "Kill", name) }
func (d *krunDriver) Down(name string) error  { return hostTODO("krun", "Down", name) }
func (d *krunDriver) List() ([]Status, error) { return nil, nil }

// ---------------------------------------------------------------------------
// stubDriver — a declared-but-unbuilt backend. Preflight explains the
// requirement; lifecycle calls fail clearly rather than pretending.
// ---------------------------------------------------------------------------

type stubDriver struct {
	name  model.Driver
	needs string
}

func (s *stubDriver) Name() model.Driver { return s.name }
func (s *stubDriver) Preflight(model.Profile) error {
	return fmt.Errorf("driver %q is not implemented in this build; it needs %s", s.name, s.needs)
}
func (s *stubDriver) Up(UpSpec) (*Status, error) { return nil, s.Preflight("") }
func (s *stubDriver) Shell(string) error         { return s.Preflight("") }
func (s *stubDriver) Kill(string) error          { return s.Preflight("") }
func (s *stubDriver) Down(string) error          { return s.Preflight("") }
func (s *stubDriver) List() ([]Status, error)    { return nil, nil }

// hostTODO is the explicit phase-0 boundary marker: the code path is designed
// and reachable, but performing it correctly requires a real host with the VMM
// installed, so it is completed in phase 1 rather than faked here.
func hostTODO(drv, op, name string) error {
	return fmt.Errorf("%s.%s(%s): requires a host with libkrun/krunvm to execute; "+
		"phase 0 ships the manifest, policy compiler and CLI. Use `nullbox render` to "+
		"inspect the egress policy that will be applied", drv, op, name)
}
