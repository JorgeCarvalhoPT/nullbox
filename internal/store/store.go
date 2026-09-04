// Package store is the persistent engagement registry.
//
// Phase 0 lifecycle commands took a manifest path so the driver could be
// resolved. With a store, `up` records what it created and `kill`/`down`/
// `shell`/`list` operate on a bare engagement name — and, crucially, `kill`
// works even when the manifest is gone.
//
// One JSON file per engagement under the state dir. Stdlib only, so it is fully
// unit-testable on any platform.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Record is the persisted view of one engagement.
type Record struct {
	Name         string       `json:"name"`
	Client       string       `json:"client,omitempty"`
	Driver       string       `json:"driver"`
	Profile      string       `json:"profile"`
	ImageRef     string       `json:"imageRef"`
	Workspace    string       `json:"workspace,omitempty"`
	ManifestPath string       `json:"manifestPath,omitempty"`
	AuthRef      string       `json:"authRef,omitempty"`
	WindowEnd    string       `json:"windowEnd"`
	CreatedAt    time.Time    `json:"createdAt"`
	State        string       `json:"state"`
	MCPPort      int          `json:"mcpPort,omitempty"`
	Scope        []ScopeEntry `json:"scope,omitempty"`
}

// ScopeEntry is one authorized-or-denied destination, rendered for display.
type ScopeEntry struct {
	Target string `json:"target"` // e.g. "10.20.5.0/24:443,8443" or "portal.acme.example"
	Kind   string `json:"kind"`   // "allow" | "deny"
}

// Dir returns the state directory, honoring NULLBOX_STATE for tests and custom
// layouts, else <user-config-dir>/nullbox.
func Dir() (string, error) {
	if d := os.Getenv("NULLBOX_STATE"); d != "" {
		return d, nil
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve state dir: %w", err)
	}
	return filepath.Join(cfg, "nullbox"), nil
}

func pathFor(name string) (string, error) {
	if err := validName(name); err != nil {
		return "", err
	}
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name+".json"), nil
}

// validName rejects anything that could escape the state dir or collide with
// the filesystem. Engagement names are DNS labels, so this is strict.
func validName(name string) error {
	if name == "" {
		return fmt.Errorf("empty engagement name")
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return fmt.Errorf("invalid engagement name %q", name)
	}
	return nil
}

// Save writes (or replaces) a record atomically.
func Save(r Record) error {
	p, err := pathFor(r.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Load reads one record by name.
func Load(name string) (Record, error) {
	p, err := pathFor(name)
	if err != nil {
		return Record{}, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Record{}, fmt.Errorf("no engagement named %q (try `nullbox list`)", name)
		}
		return Record{}, err
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return Record{}, fmt.Errorf("corrupt record %s: %w", p, err)
	}
	return r, nil
}

// List returns all records, newest first.
func List() ([]Record, error) {
	d, err := Dir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no state dir yet => no engagements
		}
		return nil, err
	}
	var out []Record
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		r, err := Load(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			continue // skip corrupt/partial files rather than failing the whole list
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Delete removes a record. Missing is not an error (idempotent teardown).
func Delete(name string) error {
	p, err := pathFor(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
