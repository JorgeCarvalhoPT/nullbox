package engage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

func TestParseTargets(t *testing.T) {
	ts, err := ParseTargets("10.10.0.0/16 10.20.5.0/24:443,8443 host.example.com app.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 4 {
		t.Fatalf("got %d targets", len(ts))
	}
	if ts[0].CIDR != "10.10.0.0/16" || len(ts[0].Ports) != 0 {
		t.Errorf("t0 = %+v", ts[0])
	}
	if ts[1].CIDR != "10.20.5.0/24" || len(ts[1].Ports) != 2 || ts[1].Ports[0] != 443 || ts[1].Ports[1] != 8443 {
		t.Errorf("t1 = %+v", ts[1])
	}
	if ts[2].Host != "host.example.com" {
		t.Errorf("t2 = %+v", ts[2])
	}
	if ts[3].Host != "app.example.com" || len(ts[3].Ports) != 1 || ts[3].Ports[0] != 443 {
		t.Errorf("t3 = %+v", ts[3])
	}
	if _, err := ParseTargets("10.0.0.0/8:notaport"); err == nil {
		t.Error("a non-numeric port must error")
	}
}

func TestWriteManifest(t *testing.T) {
	dir := t.TempDir()
	e := &model.Engagement{APIVersion: "nullbox/v1", Kind: "Engagement", Metadata: model.Metadata{Name: "x"}}
	p, err := WriteManifest(e, dir)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, "x.yaml") {
		t.Errorf("path = %s", p)
	}
	if _, err := os.Stat(p); err != nil {
		t.Error("manifest not written")
	}
	if _, err := WriteManifest(e, dir); err == nil {
		t.Error("second write must refuse to overwrite")
	}
}

func TestImageRef(t *testing.T) {
	if ImageRef(&model.Engagement{Spec: model.Spec{Image: "custom:1"}}) != "custom:1" {
		t.Error("manifest image should win")
	}
	if ImageRef(&model.Engagement{Spec: model.Spec{Capabilities: model.Capabilities{InfraTools: true}}}) != "nullbox/guest:full" {
		t.Error("infraTools => full default")
	}
	if ImageRef(&model.Engagement{}) != "nullbox/guest:thin" {
		t.Error("default => thin")
	}
}
