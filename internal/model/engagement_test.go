package model

import "testing"

func valid() *Engagement {
	return &Engagement{
		APIVersion: "nullbox/v1",
		Kind:       "Engagement",
		Metadata: Metadata{
			Name:          "acme",
			Authorization: Authorization{Ref: "SOW-1"},
		},
		Spec: Spec{
			Window:  Window{End: "2026-12-31T00:00:00Z"},
			Network: Network{Profile: ProfileNAT},
			Scope:   Scope{Allow: []Target{{CIDR: "203.0.113.0/24"}}},
		},
	}
}

func TestValidBaseline(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("baseline should be valid: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Engagement){
		"bad apiVersion":     func(e *Engagement) { e.APIVersion = "v1" },
		"bad kind":           func(e *Engagement) { e.Kind = "Thing" },
		"bad name":           func(e *Engagement) { e.Metadata.Name = "ACME_Corp" },
		"missing auth ref":   func(e *Engagement) { e.Metadata.Authorization.Ref = "" },
		"missing profile":    func(e *Engagement) { e.Spec.Network.Profile = "" },
		"bad profile":        func(e *Engagement) { e.Spec.Network.Profile = "wireguard" },
		"bad driver":         func(e *Engagement) { e.Spec.Driver = "virtualbox" },
		"missing window end": func(e *Engagement) { e.Spec.Window.End = "" },
		"bad window end":     func(e *Engagement) { e.Spec.Window.End = "next tuesday" },
		"empty allow":        func(e *Engagement) { e.Spec.Scope.Allow = nil },
		"cidr and host":      func(e *Engagement) { e.Spec.Scope.Allow = []Target{{CIDR: "10.0.0.0/8", Host: "x.example.com"}} },
		"neither cidr/host":  func(e *Engagement) { e.Spec.Scope.Allow = []Target{{}} },
		"bad cidr":           func(e *Engagement) { e.Spec.Scope.Allow = []Target{{CIDR: "10.0.0.0/64"}} },
		"bad host":           func(e *Engagement) { e.Spec.Scope.Allow = []Target{{Host: "not a host"}} },
		"bad port":           func(e *Engagement) { e.Spec.Scope.Allow = []Target{{CIDR: "10.0.0.0/8", Ports: []int{70000}}} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := valid()
			mutate(e)
			if err := e.Validate(); err == nil {
				t.Errorf("expected %q to be rejected, but Validate passed", name)
			}
		})
	}
}

func TestDenyMetadataDefaultsTrue(t *testing.T) {
	if !valid().Spec.Network.DenyMetadataEnabled() {
		t.Error("denyMetadata should default to true")
	}
	f := false
	n := Network{Profile: ProfileNAT, DenyMetadata: &f}
	if n.DenyMetadataEnabled() {
		t.Error("denyMetadata=false should disable")
	}
}
