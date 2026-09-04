// Package model holds the nullbox Engagement schema and its validation.
//
// It is deliberately dependency-free (stdlib only). The yaml struct tags are
// inert here — they are read reflectively by the loader in package manifest,
// which owns the one external dependency (gopkg.in/yaml.v3). Keeping the types
// and their validation stdlib-only lets package policy and its tests compile
// and run with no modules present.
package model

import (
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

// Profile is the network attachment model. It selects, together with the
// driver, exactly what traffic can leave the microVM.
type Profile string

const (
	// ProfileNAT — routed TCP/UDP/ICMP-echo via user-mode networking
	// (passt/TSI). Works on the krun driver on macOS and Linux. The default.
	ProfileNAT Profile = "nat"
	// ProfileRouted — TAP + host nftables, full raw sockets / UDP / ICMP to
	// routable CIDRs. Linux drivers only (firecracker/clh/kata).
	ProfileRouted Profile = "routed"
	// ProfileL2 — bridged TAP (Linux) or a SOCK_DGRAM L2 socket (macOS),
	// placing the guest on a real broadcast domain for arp-scan / Responder /
	// mitm6. Placement-bound: the host must physically sit on the target
	// segment.
	ProfileL2 Profile = "l2"
)

// Driver names the VMM backend. The manifest may pin one; if empty the CLI
// selects a default from the host and the requested profile.
type Driver string

const (
	DriverKrun        Driver = "krun"        // laptop: libkrun/krunvm, macOS HVF + Linux KVM
	DriverFirecracker Driver = "firecracker" // Linux server: Firecracker + TAP
	DriverCLH         Driver = "clh"         // Linux server: Cloud Hypervisor + TAP
	DriverKata        Driver = "kata"        // cluster: Kata on Kubernetes
)

// Engagement is the top-level manifest.
type Engagement struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name          string        `yaml:"name"`          // stable engagement id, used for VM/namespace/port naming
	Client        string        `yaml:"client"`        // human label, for reports
	Authorization Authorization `yaml:"authorization"` // the paper trail
}

type Authorization struct {
	Ref     string `yaml:"ref"`     // SOW / ticket reference
	Contact string `yaml:"contact"` // client-side authorizing contact
	Signed  string `yaml:"signed"`  // ISO date the authorization was signed
}

type Spec struct {
	// Template names a saved config preset whose defaults fill the fields this
	// manifest leaves unset (driver, image, network, capabilities, evidence).
	// Scope, window, and authorization stay per-engagement. Resolved at load.
	Template string `yaml:"template,omitempty"`
	Driver   Driver `yaml:"driver,omitempty"` // optional pin; empty => auto
	// Image is the guest OCI image — ANY AI pentesting agent. nullbox is
	// agent-agnostic: the sandbox does not care what runs inside. Empty => a
	// built-in default guest chosen from Capabilities.InfraTools.
	Image        string       `yaml:"image,omitempty"`
	Window       Window       `yaml:"window"` // egress auto-expires at end
	Scope        Scope        `yaml:"scope"`  // the allow/deny list = authorization
	Network      Network      `yaml:"network"`
	Capabilities Capabilities `yaml:"capabilities"`
	Workspace    string       `yaml:"workspace,omitempty"` // host path mounted as the target codebase
	Evidence     Evidence     `yaml:"evidence"`
}

// Window bounds the engagement in time. End drives an automatic policy flush so
// scope cannot outlive its authorization.
type Window struct {
	Start string `yaml:"start"` // RFC3339; informational
	End   string `yaml:"end"`   // RFC3339; egress is revoked at/after this instant
}

// Scope is the heart of the manifest. Allowed destinations are reachable;
// everything else is dropped by default. Deny always wins over allow.
type Scope struct {
	Allow []Target `yaml:"allow"`
	Deny  []Target `yaml:"deny,omitempty"`
}

// Target is exactly one of cidr or host (with optional ports). Validation
// enforces the exclusivity.
type Target struct {
	CIDR  string `yaml:"cidr,omitempty"`  // e.g. 203.0.113.0/24 or a single 10.1.2.3/32
	Host  string `yaml:"host,omitempty"`  // FQDN, may be a *.example.com wildcard
	Ports []int  `yaml:"ports,omitempty"` // empty => all ports
}

type Network struct {
	Profile Profile `yaml:"profile"`
	// DenyMetadata defaults true: always block 169.254.169.254 and the
	// link-local range so offensive tooling cannot reach host/cloud
	// credentials. Set false ONLY for a deliberate, authorized IMDS test.
	DenyMetadata *bool `yaml:"denyMetadata,omitempty"`
}

type Capabilities struct {
	// InfraTools selects the "full" guest image variant (Kali infra domain:
	// masscan, netexec, responder, arp-scan…). Requires routed or l2 profile
	// to be useful.
	InfraTools bool `yaml:"infraTools,omitempty"`
}

type Evidence struct {
	// RetainFlows enables per-engagement egress flow logging (allowed AND
	// denied) as engagement evidence.
	RetainFlows bool `yaml:"retainFlows,omitempty"`
	RetainDays  int  `yaml:"retainDays,omitempty"`
}

var (
	nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// A permissive hostname / wildcard matcher. A leading "*." is allowed once.
	hostRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
)

// Validate enforces the invariants the rest of the system relies on. It is
// intentionally strict: a malformed scope is a legal problem, not a warning.
func (e *Engagement) Validate() error {
	if e.APIVersion != "nullbox/v1" {
		return fmt.Errorf("apiVersion must be nullbox/v1, got %q", e.APIVersion)
	}
	if e.Kind != "Engagement" {
		return fmt.Errorf("kind must be Engagement, got %q", e.Kind)
	}
	if !nameRe.MatchString(e.Metadata.Name) {
		return fmt.Errorf("metadata.name %q must be a DNS label (lowercase alnum + dashes)", e.Metadata.Name)
	}
	if e.Metadata.Authorization.Ref == "" {
		return fmt.Errorf("metadata.authorization.ref is required — the manifest is the authorization record")
	}

	switch e.Spec.Network.Profile {
	case ProfileNAT, ProfileRouted, ProfileL2:
	case "":
		return fmt.Errorf("spec.network.profile is required (nat|routed|l2)")
	default:
		return fmt.Errorf("spec.network.profile %q is not one of nat|routed|l2", e.Spec.Network.Profile)
	}

	if e.Spec.Driver != "" {
		switch e.Spec.Driver {
		case DriverKrun, DriverFirecracker, DriverCLH, DriverKata:
		default:
			return fmt.Errorf("spec.driver %q is not one of krun|firecracker|clh|kata", e.Spec.Driver)
		}
	}

	// Window.End is mandatory and must parse; scope must not outlive its
	// authorization.
	if e.Spec.Window.End == "" {
		return fmt.Errorf("spec.window.end is required — egress auto-expires at this instant")
	}
	if _, err := time.Parse(time.RFC3339, e.Spec.Window.End); err != nil {
		return fmt.Errorf("spec.window.end %q is not RFC3339: %w", e.Spec.Window.End, err)
	}
	if e.Spec.Window.Start != "" {
		if _, err := time.Parse(time.RFC3339, e.Spec.Window.Start); err != nil {
			return fmt.Errorf("spec.window.start %q is not RFC3339: %w", e.Spec.Window.Start, err)
		}
	}

	if len(e.Spec.Scope.Allow) == 0 {
		return fmt.Errorf("spec.scope.allow is empty — an engagement with no scope can reach nothing; state the scope explicitly")
	}
	for i, t := range e.Spec.Scope.Allow {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("spec.scope.allow[%d]: %w", i, err)
		}
	}
	for i, t := range e.Spec.Scope.Deny {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("spec.scope.deny[%d]: %w", i, err)
		}
	}
	return nil
}

// Validate checks a single scope target.
func (t Target) Validate() error {
	hasCIDR, hasHost := t.CIDR != "", t.Host != ""
	if hasCIDR == hasHost {
		return fmt.Errorf("each target must set exactly one of cidr or host")
	}
	if hasCIDR {
		if _, err := netip.ParsePrefix(t.CIDR); err != nil {
			return fmt.Errorf("cidr %q: %w", t.CIDR, err)
		}
	}
	if hasHost && !hostRe.MatchString(t.Host) {
		return fmt.Errorf("host %q is not a valid FQDN or *.wildcard", t.Host)
	}
	for _, p := range t.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d out of range 1-65535", p)
		}
	}
	return nil
}

// DenyMetadataEnabled reports the effective value (defaults true when unset).
func (n Network) DenyMetadataEnabled() bool {
	return n.DenyMetadata == nil || *n.DenyMetadata
}

// Expired reports whether the engagement window has closed relative to now.
func (e *Engagement) Expired(now time.Time) bool {
	end, err := time.Parse(time.RFC3339, e.Spec.Window.End)
	if err != nil {
		return false // Validate() already guarantees it parses; be safe.
	}
	return now.After(end)
}
