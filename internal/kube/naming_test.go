package kube

import (
	"strings"
	"testing"
)

func TestNamespace(t *testing.T) {
	if got := Namespace("acme-internal"); got != "nbx-acme-internal" {
		t.Errorf("Namespace = %q, want nbx-acme-internal", got)
	}
	// A 63-char engagement name would overflow with the nbx- prefix -> hash-suffixed, still <=63.
	long := strings.Repeat("a", 63)
	got := Namespace(long)
	if len(got) > maxDNSLabel {
		t.Errorf("Namespace(%d chars) = %d chars, must be <= 63", len(long), len(got))
	}
	if !strings.HasPrefix(got, "nbx-") {
		t.Errorf("overflowed namespace lost its prefix: %q", got)
	}
}

func TestLabelsStable(t *testing.T) {
	l := Labels("acme-internal", "agent")
	if l[LabelEngagement] != "acme-internal" || l[LabelComponent] != "agent" || l[LabelManagedBy] != "nullbox" {
		t.Errorf("labels drifted: %+v", l)
	}
	// The kata driver's NetworkPolicy selector and the runner's pod labels must
	// agree — same engagement+component => identical map.
	a := Labels("x", "tool")
	b := Labels("x", "tool")
	for k, v := range a {
		if b[k] != v {
			t.Errorf("label %q unstable: %q vs %q", k, v, b[k])
		}
	}
}

func TestRuntimeClass(t *testing.T) {
	if RuntimeClass() != "kata" {
		t.Errorf("RuntimeClass = %q, want kata", RuntimeClass())
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("Acme_Internal.01"); got != "acme-internal-01" {
		t.Errorf("sanitize = %q", got)
	}
}
