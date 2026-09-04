// Package kube holds the pure Kubernetes naming shared by the kata driver and
// the tool runner, so a sibling tool Pod is guaranteed to carry the exact
// labels the engagement's NetworkPolicy selects. Stdlib only — fully testable
// off-cluster. If these strings drift between the two callers, tool egress goes
// unscoped (fail-open), so they live in one place.
package kube

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

const (
	// LabelEngagement tags every object with its engagement id.
	LabelEngagement = "nullbox.dev/engagement"
	// LabelComponent distinguishes the agent pod from tool pods.
	LabelComponent = "nullbox.dev/component"
	// LabelManagedBy marks everything nullbox owns.
	LabelManagedBy = "app.kubernetes.io/managed-by"

	managedByValue = "nullbox"
	nsPrefix       = "nbx-"
	maxDNSLabel    = 63
)

// Namespace returns the per-engagement namespace ("nbx-<name>"), hash-suffixed
// if "nbx-"+name would exceed the 63-char DNS-1123 label limit.
func Namespace(engagement string) string {
	return dns1123("nbx-" + engagement)
}

// RuntimeClass is the RuntimeClass name a Kata-enabled cluster exposes.
func RuntimeClass() string { return "kata" }

// Labels are the labels every object for an engagement carries. component is
// "agent" for the engagement pod, "tool" for a sibling tool job.
func Labels(engagement, component string) map[string]string {
	return map[string]string{
		LabelEngagement: dnsValue(engagement),
		LabelComponent:  component,
		LabelManagedBy:  managedByValue,
	}
}

// ManagedSelector is the label set that matches everything nullbox created,
// for `kubectl get -l`.
func ManagedSelector() string { return LabelManagedBy + "=" + managedByValue }

// dns1123 clamps a name to a valid <=63-char DNS-1123 label, hash-suffixing when
// it is too long so the result stays unique.
func dns1123(s string) string {
	s = sanitize(s)
	if len(s) <= maxDNSLabel {
		return s
	}
	h := sha1.Sum([]byte(s))
	suf := "-" + hex.EncodeToString(h[:])[:8]
	keep := maxDNSLabel - len(suf)
	return strings.TrimRight(s[:keep], "-") + suf
}

// dnsValue clamps a label value the same way (values share the 63-char limit).
func dnsValue(s string) string { return dns1123(s) }

// sanitize lowercases and replaces any char outside [a-z0-9-] so a name is a
// valid DNS-1123 label; trims leading/trailing dashes.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
