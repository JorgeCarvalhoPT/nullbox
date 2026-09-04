// Package engage is the shared engagement orchestration used by both the CLI
// and the TUI: resolving the guest image, compiling the policy, selecting the
// driver, booting, and recording the engagement. Keeping it here means the
// terminal "new engagement" form and `nullbox up` take the exact same path.
package engage

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/JorgeCarvalhoPT/nullbox/internal/driver"
	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/policy"
	"github.com/JorgeCarvalhoPT/nullbox/internal/store"
)

// ImageRef resolves the guest OCI image — any AI pentesting agent. The manifest
// wins (spec.image); otherwise a built-in default guest by infraTools.
func ImageRef(e *model.Engagement) string {
	if e.Spec.Image != "" {
		return e.Spec.Image
	}
	if e.Spec.Capabilities.InfraTools {
		return "nullbox/guest:full"
	}
	return "nullbox/guest:thin"
}

// ScopeEntries renders the manifest's scope for display in the store/console.
func ScopeEntries(e *model.Engagement) []store.ScopeEntry {
	var out []store.ScopeEntry
	add := func(ts []model.Target, kind string) {
		for _, t := range ts {
			out = append(out, store.ScopeEntry{Target: TargetStr(t), Kind: kind})
		}
	}
	add(e.Spec.Scope.Allow, "allow")
	add(e.Spec.Scope.Deny, "deny")
	return out
}

// TargetStr renders a scope target, e.g. "10.20.5.0/24:443,8443" or a host.
func TargetStr(t model.Target) string {
	base := t.CIDR
	if base == "" {
		base = t.Host
	}
	if len(t.Ports) > 0 {
		parts := make([]string, len(t.Ports))
		for i, p := range t.Ports {
			parts[i] = strconv.Itoa(p)
		}
		base += ":" + strings.Join(parts, ",")
	}
	return base
}

// ParseTargets parses whitespace-separated scope tokens, each an optional
// "target:port,port". A token with "/" is a CIDR, otherwise a host.
func ParseTargets(s string) ([]model.Target, error) {
	var out []model.Target
	for _, tok := range strings.Fields(s) {
		host, portsStr, _ := strings.Cut(tok, ":")
		var ports []int
		if portsStr != "" {
			for _, p := range strings.Split(portsStr, ",") {
				n, err := strconv.Atoi(strings.TrimSpace(p))
				if err != nil {
					return nil, fmt.Errorf("bad port %q in %q", p, tok)
				}
				ports = append(ports, n)
			}
		}
		t := model.Target{Ports: ports}
		if strings.Contains(host, "/") {
			t.CIDR = host
		} else {
			t.Host = host
		}
		out = append(out, t)
	}
	return out, nil
}

// WriteManifest marshals an engagement to <dir>/<name>.yaml (dir "" => cwd) and
// returns the path. It refuses to overwrite an existing file.
func WriteManifest(e *model.Engagement, dir string) (string, error) {
	if dir == "" {
		dir = "."
	}
	path := filepath.Join(dir, e.Metadata.Name+".yaml")
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists", path)
	}
	b, err := yaml.Marshal(e)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// Up compiles, selects the driver, preflights, boots, and records the
// engagement. Returns the driver status and the saved record.
func Up(e *model.Engagement, workspace, manifestPath string) (*driver.Status, store.Record, error) {
	rs, err := policy.Compile(e)
	if err != nil {
		return nil, store.Record{}, err
	}
	d, err := driver.Select(e)
	if err != nil {
		return nil, store.Record{}, err
	}
	if err := d.Preflight(e.Spec.Network.Profile); err != nil {
		return nil, store.Record{}, err
	}
	st, err := d.Up(driver.UpSpec{Engagement: e, Ruleset: rs, ImageRef: ImageRef(e), Workspace: workspace})
	if err != nil {
		return nil, store.Record{}, err
	}
	rec := store.Record{
		Name:         e.Metadata.Name,
		Client:       e.Metadata.Client,
		Driver:       string(d.Name()),
		Profile:      string(e.Spec.Network.Profile),
		ImageRef:     ImageRef(e),
		Workspace:    workspace,
		ManifestPath: manifestPath,
		AuthRef:      e.Metadata.Authorization.Ref,
		WindowEnd:    e.Spec.Window.End,
		CreatedAt:    time.Now(),
		State:        st.State,
		MCPPort:      st.MCPPort,
		Scope:        ScopeEntries(e),
	}
	if err := store.Save(rec); err != nil {
		return st, rec, fmt.Errorf("engagement started but recording it failed: %w", err)
	}
	return st, rec, nil
}
