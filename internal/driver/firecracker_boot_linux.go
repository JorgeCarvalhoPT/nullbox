//go:build linux

package driver

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/JorgeCarvalhoPT/nullbox/internal/contract"
	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/store"
)

// Register the firecracker driver with the real booter wired in.
func init() { register(&fcDriver{boot: firecrackerBoot(loadFCConfig())}) }

// loadFCConfig builds the Firecracker Config from env + defaults. The kernel and
// rootfs are engagement-independent assets provisioned on the host.
func loadFCConfig() Config {
	env := func(k, d string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return d
	}
	return Config{
		FirecrackerBin:  env("NULLBOX_FC_BIN", "firecracker"),
		KernelImagePath: env("NULLBOX_FC_KERNEL", "/opt/nullbox/vmlinux"),
		RootfsPath:      env("NULLBOX_FC_ROOTFS", "/opt/nullbox/rootfs.ext4"),
		VCPUs:           2,
		MemMiB:          2048,
		RunDir:          fcRunDir(),
		GuestIP:         fcGuestIP,
		HostTapIP:       fcHostTapIP,
		Netmask:         fcNetmask,
		GuestMAC:        fcGuestMAC,
	}
}

func fcRunDir() string {
	if v := os.Getenv("NULLBOX_FC_RUNDIR"); v != "" {
		return v
	}
	if d, err := store.Dir(); err == nil {
		return filepath.Join(d, "run")
	}
	return "/run/nullbox"
}

// firecrackerBoot returns a bootFunc: it stages the capability contract, spawns
// firecracker against a per-engagement API socket, waits for readiness, drives
// the config API, and starts the instance.
func firecrackerBoot(cfg Config) bootFunc {
	return func(spec UpSpec, tap string) (*Status, error) {
		name := spec.Engagement.Metadata.Name
		if err := os.MkdirAll(cfg.RunDir, 0o700); err != nil {
			return nil, fmt.Errorf("run dir: %w", err)
		}
		// Stage the generated capability contract into the guest home overlay so
		// the agent reads its own limits. (The rootfs overlay that mounts this is
		// host-specific; writing the file is what this package owns.)
		home := filepath.Join(cfg.RunDir, name, "guest-root")
		if _, err := contract.WriteInto(home, spec.Engagement); err != nil {
			fmt.Fprintf(os.Stderr, "nullbox: contract staging: %v\n", err)
		}

		sock := filepath.Join(cfg.RunDir, name+".sock")
		_ = os.Remove(sock) // firecracker refuses a stale socket
		logf, _ := os.Create(filepath.Join(cfg.RunDir, name+".console.log"))

		cmd := exec.Command(cfg.firecrackerBin(), "--api-sock", sock, "--id", name)
		if logf != nil {
			cmd.Stdout = logf
			cmd.Stderr = logf
		}
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("start firecracker: %w", err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()

		if err := waitSocket(sock, done); err != nil {
			_ = cmd.Process.Kill()
			return nil, err
		}
		a := newFCAPI(sock)
		if err := a.configure(cfg, tap); err != nil {
			_ = cmd.Process.Kill()
			return nil, err
		}
		if err := a.start(); err != nil {
			_ = cmd.Process.Kill()
			return nil, err
		}
		return &Status{Name: name, Driver: model.DriverFirecracker, State: "running", MCPPort: 0}, nil
	}
}

// waitSocket polls the API socket until it accepts a connection, bailing early
// if firecracker exits.
func waitSocket(sock string, done <-chan error) error {
	for i := 0; i < 60; i++ {
		select {
		case err := <-done:
			return fmt.Errorf("firecracker exited before its API socket was ready: %v", err)
		default:
		}
		if c, err := net.Dial("unix", sock); err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("firecracker API socket %s not ready after 3s", sock)
}

// ensureIPForward turns on IPv4 forwarding so the host routes guest egress.
func ensureIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
}

// defaultUplink returns the interface of the default route (masquerade target),
// or "" to let the policy masquerade on any non-tap interface.
func defaultUplink() string {
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
