// Package template stores reusable engagement configuration presets. A template
// captures the non-authorization knobs — driver, guest image, network profile,
// capabilities, evidence — so many engagements share one setup, while scope,
// window, and authorization stay per-engagement. A manifest opts in with
// `spec.template: <name>`; the template fills only the fields the manifest
// leaves unset (the manifest always wins).
//
// Templates are YAML files under the templates dir (NULLBOX_TEMPLATES, else
// <user-config>/nullbox/templates).
package template

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

// Template is a reusable config preset.
type Template struct {
	Name         string             `yaml:"name"`
	Driver       model.Driver       `yaml:"driver,omitempty"`
	Image        string             `yaml:"image,omitempty"`
	Network      model.Network      `yaml:"network,omitempty"`
	Capabilities model.Capabilities `yaml:"capabilities,omitempty"`
	Evidence     model.Evidence     `yaml:"evidence,omitempty"`
}

// Dir returns the templates directory.
func Dir() string {
	if d := os.Getenv("NULLBOX_TEMPLATES"); d != "" {
		return d
	}
	if c, err := os.UserConfigDir(); err == nil {
		return filepath.Join(c, "nullbox", "templates")
	}
	return filepath.Join(os.TempDir(), "nullbox-templates")
}

func pathFor(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return "", fmt.Errorf("invalid template name %q", name)
	}
	return filepath.Join(Dir(), name+".yaml"), nil
}

// Save writes (or replaces) a template atomically.
func Save(t Template) error {
	p, err := pathFor(t.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(t)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Load reads a template by name.
func Load(name string) (Template, error) {
	p, err := pathFor(name)
	if err != nil {
		return Template{}, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Template{}, fmt.Errorf("no template named %q (see `nullbox template list`)", name)
		}
		return Template{}, err
	}
	var t Template
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return Template{}, fmt.Errorf("parse template %s: %w", p, err)
	}
	return t, nil
}

// List returns the saved template names, sorted.
func List() ([]string, error) {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
	}
	sort.Strings(names)
	return names, nil
}

// ApplyTo fills a spec's non-authorization fields from the template where the
// spec leaves them at their zero value. The manifest always wins where set.
func (t Template) ApplyTo(s *model.Spec) {
	if s.Driver == "" {
		s.Driver = t.Driver
	}
	if s.Image == "" {
		s.Image = t.Image
	}
	if s.Network.Profile == "" {
		s.Network.Profile = t.Network.Profile
	}
	if s.Network.DenyMetadata == nil {
		s.Network.DenyMetadata = t.Network.DenyMetadata
	}
	if !s.Capabilities.InfraTools {
		s.Capabilities.InfraTools = t.Capabilities.InfraTools
	}
	if !s.Evidence.RetainFlows {
		s.Evidence.RetainFlows = t.Evidence.RetainFlows
	}
	if s.Evidence.RetainDays == 0 {
		s.Evidence.RetainDays = t.Evidence.RetainDays
	}
}

// FromSpec captures the reusable config knobs of a spec as a template.
func FromSpec(name string, s model.Spec) Template {
	return Template{
		Name:         name,
		Driver:       s.Driver,
		Image:        s.Image,
		Network:      model.Network{Profile: s.Network.Profile, DenyMetadata: s.Network.DenyMetadata},
		Capabilities: s.Capabilities,
		Evidence:     s.Evidence,
	}
}
