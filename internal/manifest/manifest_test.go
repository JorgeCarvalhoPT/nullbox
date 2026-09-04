package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/template"
)

func writeManifest(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "e.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadResolvesTemplate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NULLBOX_TEMPLATES", dir)
	if err := template.Save(template.Template{
		Name: "std", Driver: model.DriverFirecracker, Image: "img:1",
		Network:      model.Network{Profile: model.ProfileRouted},
		Capabilities: model.Capabilities{InfraTools: true},
	}); err != nil {
		t.Fatal(err)
	}
	// The manifest supplies only per-engagement fields; the rest come from the template.
	mf := writeManifest(t, dir, `apiVersion: nullbox/v1
kind: Engagement
metadata: { name: acme, authorization: { ref: SOW-1 } }
spec:
  template: std
  window: { end: "2026-12-31T00:00:00Z" }
  scope: { allow: [ { cidr: 10.0.0.0/8 } ] }
`)
	e, err := Load(mf)
	if err != nil {
		t.Fatal(err)
	}
	if e.Spec.Driver != model.DriverFirecracker || e.Spec.Image != "img:1" ||
		e.Spec.Network.Profile != model.ProfileRouted || !e.Spec.Capabilities.InfraTools {
		t.Errorf("template not merged: %+v", e.Spec)
	}
}

func TestLoadManifestOverridesTemplate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NULLBOX_TEMPLATES", dir)
	_ = template.Save(template.Template{Name: "std", Driver: model.DriverFirecracker, Network: model.Network{Profile: model.ProfileRouted}})
	mf := writeManifest(t, dir, `apiVersion: nullbox/v1
kind: Engagement
metadata: { name: acme, authorization: { ref: SOW-1 } }
spec:
  template: std
  network: { profile: nat }
  window: { end: "2026-12-31T00:00:00Z" }
  scope: { allow: [ { host: app.example.com } ] }
`)
	e, err := Load(mf)
	if err != nil {
		t.Fatal(err)
	}
	if e.Spec.Network.Profile != model.ProfileNAT {
		t.Errorf("manifest profile must override template, got %q", e.Spec.Network.Profile)
	}
}

func TestLoadMissingTemplateErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NULLBOX_TEMPLATES", dir)
	mf := writeManifest(t, dir, `apiVersion: nullbox/v1
kind: Engagement
metadata: { name: acme, authorization: { ref: SOW-1 } }
spec:
  template: nonexistent
  network: { profile: nat }
  window: { end: "2026-12-31T00:00:00Z" }
  scope: { allow: [ { cidr: 10.0.0.0/8 } ] }
`)
	if _, err := Load(mf); err == nil {
		t.Error("a missing template must error, not silently ignore")
	}
}
