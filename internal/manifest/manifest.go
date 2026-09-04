// Package manifest loads an Engagement manifest from YAML, resolving any
// `spec.template` preset before validation.
//
// This and internal/template are the only packages that depend on
// gopkg.in/yaml.v3. The schema and validation live in package model.
package manifest

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/template"
)

// Load reads, template-resolves, and validates a manifest file.
func Load(path string) (*model.Engagement, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	e, err := decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if e.Spec.Template != "" {
		t, err := template.Load(e.Spec.Template)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		t.ApplyTo(&e.Spec)
	}
	if err := e.Validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", path, err)
	}
	return e, nil
}

// Parse decodes and validates manifest bytes WITHOUT template resolution
// (templates are file-based — use Load for those).
func Parse(raw []byte) (*model.Engagement, error) {
	e, err := decode(raw)
	if err != nil {
		return nil, err
	}
	if err := e.Validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}
	return e, nil
}

// decode parses manifest YAML, rejecting unknown keys so a typo fails loudly.
func decode(raw []byte) (*model.Engagement, error) {
	var e model.Engagement
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &e, nil
}
