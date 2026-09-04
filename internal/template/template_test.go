package template

import (
	"testing"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

func TestSaveLoadListApply(t *testing.T) {
	t.Setenv("NULLBOX_TEMPLATES", t.TempDir())
	f := false
	tpl := Template{
		Name:         "acme-standard",
		Driver:       model.DriverFirecracker,
		Image:        "ghcr.io/acme/agent:v1",
		Network:      model.Network{Profile: model.ProfileRouted, DenyMetadata: &f},
		Capabilities: model.Capabilities{InfraTools: true},
		Evidence:     model.Evidence{RetainFlows: true, RetainDays: 400},
	}
	if err := Save(tpl); err != nil {
		t.Fatal(err)
	}
	names, err := List()
	if err != nil || len(names) != 1 || names[0] != "acme-standard" {
		t.Fatalf("List = %v, %v", names, err)
	}
	got, err := Load("acme-standard")
	if err != nil || got.Image != "ghcr.io/acme/agent:v1" || got.Network.Profile != model.ProfileRouted {
		t.Fatalf("Load = %+v, %v", got, err)
	}

	// ApplyTo fills unset fields; the manifest wins where it set a value.
	spec := model.Spec{Network: model.Network{Profile: model.ProfileNAT}} // manifest chose nat
	got.ApplyTo(&spec)
	if spec.Network.Profile != model.ProfileNAT {
		t.Error("manifest profile must win over the template")
	}
	if spec.Driver != model.DriverFirecracker {
		t.Error("template driver should fill the unset field")
	}
	if spec.Image != "ghcr.io/acme/agent:v1" {
		t.Error("template image should fill")
	}
	if !spec.Capabilities.InfraTools {
		t.Error("template infraTools should fill")
	}
	if spec.Evidence.RetainDays != 400 {
		t.Error("template retainDays should fill")
	}
}

func TestRejectsBadName(t *testing.T) {
	t.Setenv("NULLBOX_TEMPLATES", t.TempDir())
	if err := Save(Template{Name: "../evil"}); err == nil {
		t.Error("must reject a traversal name")
	}
	if _, err := Load("a/b"); err == nil {
		t.Error("must reject a slashed name")
	}
}

func TestFromSpec(t *testing.T) {
	s := model.Spec{Driver: model.DriverKata, Image: "x:1", Network: model.Network{Profile: model.ProfileRouted}}
	tp := FromSpec("t1", s)
	if tp.Name != "t1" || tp.Driver != model.DriverKata || tp.Image != "x:1" || tp.Network.Profile != model.ProfileRouted {
		t.Errorf("FromSpec = %+v", tp)
	}
}
