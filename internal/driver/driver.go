// Package driver abstracts the VMM backend that actually runs an engagement.
//
// The same Engagement manifest and the same compiled nftables ruleset drive
// every driver — krun (laptop, libkrun/krunvm), firecracker/clh (Linux server),
// kata (K8s cluster). Phase 0 ships the krun driver only; the others are
// registered as stubs so `nullbox` reports them coherently.
package driver

import (
	"fmt"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/policy"
)

// UpSpec is everything a driver needs to bring an engagement up.
type UpSpec struct {
	Engagement *model.Engagement
	Ruleset    *policy.Ruleset // compiled egress policy
	ImageRef   string          // OCI image for the Smith guest (thin or full variant)
	Workspace  string          // host path mounted read-only as the target codebase
}

// Status is a driver's view of one engagement.
type Status struct {
	Name    string
	Driver  model.Driver
	State   string // "running" | "stopped" | "unknown"
	MCPPort int    // host port the dashboard is published on, 0 if none
}

// Driver is the lifecycle contract. Every method is expected to be idempotent.
type Driver interface {
	Name() model.Driver
	// Preflight verifies the host can run this driver with the given profile,
	// returning a clear, actionable error if not.
	Preflight(profile model.Profile) error
	Up(spec UpSpec) (*Status, error)
	Shell(name string) error
	// Kill flushes the engagement's egress ruleset immediately — the panic
	// button. It must not require the VM to be healthy.
	Kill(name string) error
	Down(name string) error
	List() ([]Status, error)
}

var registry = map[model.Driver]Driver{}

func register(d Driver) { registry[d.Name()] = d }

// Get returns the named driver, or an error listing what is available.
func Get(name model.Driver) (Driver, error) {
	d, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown driver %q (available: %s)", name, available())
	}
	return d, nil
}

// Select resolves the driver for an engagement: the manifest pin if present,
// otherwise the best default for the host and requested profile.
func Select(e *model.Engagement) (Driver, error) {
	if e.Spec.Driver != "" {
		return Get(e.Spec.Driver)
	}
	name := defaultDriver(e.Spec.Network.Profile)
	return Get(name)
}

func available() string {
	out := ""
	for n := range registry {
		if out != "" {
			out += ", "
		}
		out += string(n)
	}
	return out
}
