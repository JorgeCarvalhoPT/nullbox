package driver

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/JorgeCarvalhoPT/nullbox/internal/contract"
	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/policy"
	"github.com/JorgeCarvalhoPT/nullbox/internal/store"
)

func init() {
	register(&krunDriver{})
	// clh is a stub (a Linux server backend not yet built). firecracker registers
	// per platform (real on Linux, stub elsewhere); kata registers itself.
	register(&stubDriver{name: model.DriverCLH, needs: "a Linux host with KVM + Cloud Hypervisor"})
}

// defaultDriver picks a backend when the manifest does not pin one.
//
//   - nat    -> krun everywhere (user-mode networking, macOS + Linux)
//   - routed -> firecracker on Linux (TAP + nftables); krun cannot do raw/L2
//   - l2     -> firecracker on Linux (bridged TAP)
func defaultDriver(p model.Profile) model.Driver {
	switch p {
	case model.ProfileRouted, model.ProfileL2:
		return model.DriverFirecracker
	default:
		return model.DriverKrun
	}
}

// ---------------------------------------------------------------------------
// krun — laptop driver over libkrun/krunvm (macOS HVF + Linux KVM). Boots the
// guest OCI image as a microVM, mounts a policy bundle + workspace, publishes
// the dashboard port.
//
// SECURITY NOTE, stated honestly: there is NO host TAP or host nftables on the
// krun path, so scope cannot be enforced host-side. The guest init applies the
// SAME compiled policy in-guest (`nft -f /etc/nullbox/policy.nft`). That only
// filters egress on a real-netdev datapath (Linux/passt). On macOS libkrun uses
// TSI (socket impersonation), which bypasses the guest IP stack — so in-guest
// nft does NOT filter external traffic there. Treat macOS/krun as a dev/demo
// sandbox (process/fs/kernel isolation only); enforced engagements belong on the
// firecracker (Linux) path, which is why routed/l2 redirect there.
// ---------------------------------------------------------------------------

const (
	krunNamePrefix         = "nbx-"
	krunGuestDashPort      = 7788
	krunDefaultCPUs        = 2
	krunDefaultMemMiB      = 2048
	krunPolicyGuestPath    = "/etc/nullbox"
	krunWorkspaceGuestPath = "/workspace"
)

type krunDriver struct {
	run     func(*exec.Cmd) ([]byte, error)      // nil => real CombinedOutput
	startVM func(vm, logDir string) (int, error) // nil => real startDetached
	resolve policy.Resolver                      // nil => krunResolver
}

func (*krunDriver) Name() model.Driver { return model.DriverKrun }

func (*krunDriver) Preflight(profile model.Profile) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return fmt.Errorf("krun driver supports macOS and Linux only, not %s", runtime.GOOS)
	}
	if _, err := exec.LookPath("krunvm"); err != nil {
		return errors.New("krunvm not found in PATH — install libkrun + krunvm " +
			"(macOS: `brew tap slp/krun && brew install krunvm`; Linux: build from github.com/containers/krunvm)")
	}
	switch profile {
	case model.ProfileNAT:
		return nil
	case model.ProfileRouted, model.ProfileL2:
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
	name := spec.Engagement.Metadata.Name
	vm := krunVMName(name)

	cfg, err := d.writePolicyBundle(spec)
	if err != nil {
		return nil, err
	}
	port, err := freeTCPPort()
	if err != nil {
		return nil, fmt.Errorf("allocate dashboard port: %w", err)
	}
	_, _ = d.exec("krunvm", "delete", vm) // best-effort stale clear
	if out, err := d.exec("krunvm", krunCreateArgs(vm, spec.ImageRef, spec.Workspace, cfg, port, krunDefaultCPUs, krunDefaultMemMiB)...); err != nil {
		return nil, fmt.Errorf("krunvm create: %v: %s", err, strings.TrimSpace(string(out)))
	}
	pid, err := d.start(vm, cfg)
	if err != nil {
		_, _ = d.exec("krunvm", "delete", vm)
		return nil, fmt.Errorf("krunvm start: %w", err)
	}
	if err := writePidfile(name, pid); err != nil {
		fmt.Fprintf(os.Stderr, "nullbox: pidfile: %v\n", err)
	}
	return &Status{Name: name, Driver: model.DriverKrun, State: "running", MCPPort: port}, nil
}

// Shell boots a fresh interactive instance sharing the same volumes (krunvm has
// no exec-into-running-VM). Keep it read-mostly: it is a SEPARATE VM from the
// agent's, sharing the virtiofs workspace.
func (d *krunDriver) Shell(name string) error {
	c := exec.Command("krunvm", "start", krunVMName(name), "/bin/bash", "-l")
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

// Kill is the panic button. There is no host nft/tap to flush, so the only
// reliable egress cutoff is to tear down the VM process. Works without a healthy
// VM.
func (d *krunDriver) Kill(name string) error {
	// pid MUST be > 1: syscall.Kill(-pid, ...) signals a process GROUP, and -0 or
	// -1 would SIGKILL every process the user owns.
	if pid, err := readPidfile(name); err == nil && pid > 1 {
		_ = syscall.Kill(-pid, syscall.SIGKILL) // whole session
	}
	// Anchor the pattern so "nbx-acme" cannot also match "nbx-acme2": the agent
	// VM cmdline ends right after the name, the shell VM has a trailing space.
	_, _ = d.exec("pkill", "-f", fmt.Sprintf("krunvm start %s($| )", krunVMName(name)))
	removePidfile(name)
	return nil
}

func (d *krunDriver) Down(name string) error {
	_ = d.Kill(name)
	_, _ = d.exec("krunvm", "delete", krunVMName(name))
	_ = os.RemoveAll(filepath.Join(krunRunDir(), name))
	return nil
}

func (d *krunDriver) List() ([]Status, error) { return nil, nil }

// --- seams (nil => real) ---

func (d *krunDriver) exec(name string, args ...string) ([]byte, error) {
	c := exec.Command(name, args...)
	if d.run != nil {
		return d.run(c)
	}
	return c.CombinedOutput()
}

func (d *krunDriver) start(vm, logDir string) (int, error) {
	if d.startVM != nil {
		return d.startVM(vm, logDir)
	}
	return startDetached(vm, logDir)
}

func (d *krunDriver) resolver() policy.Resolver {
	if d.resolve != nil {
		return d.resolve
	}
	return krunResolver
}

// --- pure builders (unit-tested) ---

func krunVMName(n string) string { return krunNamePrefix + n }

func krunCreateArgs(name, image, workspace, cfgDir string, hostPort, cpus, mem int) []string {
	a := []string{"create", "--name", name, "--cpus", strconv.Itoa(cpus), "--mem", strconv.Itoa(mem),
		"--volume", cfgDir + ":" + krunPolicyGuestPath}
	if workspace != "" {
		a = append(a, "--volume", workspace+":"+krunWorkspaceGuestPath, "--workdir", krunWorkspaceGuestPath)
	}
	if hostPort != 0 {
		a = append(a, "--port", fmt.Sprintf("%d:%d", hostPort, krunGuestDashPort))
	}
	return append(a, image)
}

func krunStartArgs(name string, cmd ...string) []string {
	return append([]string{"start", name}, cmd...)
}

// --- helpers ---

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// writePolicyBundle materializes the compiled policy + resolved hosts + the
// capability contract into a host dir that krunvm mounts into the guest.
func (d *krunDriver) writePolicyBundle(spec UpSpec) (string, error) {
	dir := filepath.Join(krunRunDir(), spec.Engagement.Metadata.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(spec.Ruleset.NFT)
	if len(spec.Ruleset.UnresolvedHosts) > 0 {
		res, err := policy.ResolveHostRules(spec.Ruleset.UnresolvedHosts, d.resolver())
		if err != nil {
			return "", err
		}
		for _, s := range res.Skipped {
			fmt.Fprintf(os.Stderr, "nullbox: host %q not admitted (%s)\n", s.Host, s.Reason)
		}
		if res.AddElements != "" {
			b.WriteString("\n# resolved host targets\n")
			b.WriteString(res.AddElements)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.nft"), []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	if _, err := contract.WriteInto(dir, spec.Engagement); err != nil {
		fmt.Fprintf(os.Stderr, "nullbox: contract: %v\n", err)
	}
	return dir, nil
}

func krunResolver(host string) ([]netip.Addr, error) {
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

func startDetached(vm, logDir string) (int, error) {
	c := exec.Command("krunvm", "start", vm)
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // own session: survives CLI exit, killable as a group
	if logDir != "" {
		if lf, err := os.Create(filepath.Join(logDir, "vm.log")); err == nil {
			c.Stdout = lf
			c.Stderr = lf
		}
	}
	if err := c.Start(); err != nil {
		return 0, err
	}
	return c.Process.Pid, nil // do NOT Wait — detached
}

func krunRunDir() string {
	if d, err := store.Dir(); err == nil {
		return filepath.Join(d, "run")
	}
	return filepath.Join(os.TempDir(), "nullbox-run")
}

func krunPidPath(name string) string { return filepath.Join(krunRunDir(), name, "vm.pid") }

func writePidfile(name string, pid int) error {
	p := krunPidPath(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(strconv.Itoa(pid)), 0o600)
}

func readPidfile(name string) (int, error) {
	b, err := os.ReadFile(krunPidPath(name))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func removePidfile(name string) { _ = os.Remove(krunPidPath(name)) }

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
