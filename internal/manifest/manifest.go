// Package manifest loads an Engagement manifest from YAML.
//
// This is the ONLY package that depends on gopkg.in/yaml.v3. The schema itself
// and all validation live in package model (stdlib only), so downstream
// packages — notably policy — stay dependency-free and offline-testable.
package manifest

import (
	"bytes"
	"fmt"
	"os"

	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"gopkg.in/yaml.v3"
)

// Load reads, parses, and validates a manifest file.
func Load(path string) (*model.Engagement, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	e, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return e, nil
}

// Parse decodes and validates manifest bytes. Unknown keys are rejected so a
// typo in a scope entry fails loudly rather than silently widening or narrowing
// the authorized surface.
func Parse(raw []byte) (*model.Engagement, error) {
	var e model.Engagement
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if err := e.Validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}
	return &e, nil
}
