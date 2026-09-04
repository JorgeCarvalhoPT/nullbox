package driver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/JorgeCarvalhoPT/nullbox/internal/kube"
	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/policy"
)

// The kata driver shells out to kubectl (a cross-platform client), so it needs
// no build tag — it runs on the operator's Mac against a remote cluster.
func init() { register(&kataDriver{}) }

type kataDriver struct {
	kubectl func(stdin []byte, args ...string) ([]byte, error) // nil => real
	resolve policy.Resolver                                    // nil => kataResolver
}

func (*kataDriver) Name() model.Driver { return model.DriverKata }

func (*kataDriver) Preflight(profile model.Profile) error {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return fmt.Errorf("kubectl not found in PATH — the kata driver applies manifests to a cluster")
	}
	switch profile {
	case model.ProfileRouted, model.ProfileNAT:
		return nil
	case model.ProfileL2:
		return fmt.Errorf("profile l2 has no faithful mapping with standard NetworkPolicy/CNI; " +
			"it needs Multus macvlan/SR-IOV and a node physically on the target segment")
	default:
		return fmt.Errorf("unknown profile %q", profile)
	}
}

func (d *kataDriver) kctl(stdin []byte, args ...string) ([]byte, error) {
	if d.kubectl != nil {
		return d.kubectl(stdin, args...)
	}
	c := exec.Command("kubectl", args...)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	return c.CombinedOutput()
}

func (d *kataDriver) resolver() policy.Resolver {
	if d.resolve != nil {
		return d.resolve
	}
	return kataResolver
}

func (d *kataDriver) Up(spec UpSpec) (*Status, error) {
	if err := d.Preflight(spec.Engagement.Spec.Network.Profile); err != nil {
		return nil, err
	}
	resolved := map[string][]netip.Addr{}
	if len(spec.Ruleset.UnresolvedHosts) > 0 {
		res, err := policy.ResolveHostRules(spec.Ruleset.UnresolvedHosts, d.resolver())
		if err != nil {
			return nil, fmt.Errorf("resolve host scope: %w", err)
		}
		for _, s := range res.Skipped {
			fmt.Fprintf(os.Stderr, "nullbox: host %q not admitted (%s)\n", s.Host, s.Reason)
		}
		resolved = res.Resolved
	}
	manifest, err := renderManifests(spec, resolved)
	if err != nil {
		return nil, err
	}
	if out, err := d.kctl(manifest, "apply", "-f", "-"); err != nil {
		return nil, fmt.Errorf("kubectl apply: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return &Status{Name: spec.Engagement.Metadata.Name, Driver: model.DriverKata, State: "running", MCPPort: 0}, nil
}

func (d *kataDriver) Shell(name string) error {
	c := exec.Command("kubectl", "exec", "-it", "-n", kube.Namespace(name), "agent", "--", "/bin/bash")
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

// Kill isolates the engagement. It applies a deny-all-egress lockdown FIRST (so
// isolation is never dropped), then DELETES the allow policy. NetworkPolicies
// are additive — a union of allows — so a deny-all alongside the still-present
// nbx-scope would be a no-op; the scope policy must be removed for the deny-all
// to actually isolate the pod. Idempotent; needs no healthy pod.
func (d *kataDriver) Kill(name string) error {
	lock, err := renderLockdown(name)
	if err != nil {
		return err
	}
	if out, err := d.kctl(lock, "apply", "-f", "-"); err != nil {
		return fmt.Errorf("kubectl apply lockdown: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := d.kctl(nil, "delete", "networkpolicy", "nbx-scope", "-n", kube.Namespace(name), "--ignore-not-found=true"); err != nil {
		return fmt.Errorf("kubectl delete scope policy: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *kataDriver) Down(name string) error {
	_, _ = d.kctl(nil, "delete", "namespace", kube.Namespace(name), "--ignore-not-found=true", "--wait=false")
	return nil
}

func (d *kataDriver) List() ([]Status, error) {
	out, err := d.kctl(nil, "get", "pods", "-A", "-l", kube.LabelComponent+"=agent,"+kube.ManagedSelector(), "-o", "json")
	if err != nil {
		return nil, nil
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal(out, &list) != nil {
		return nil, nil
	}
	var sts []Status
	for _, it := range list.Items {
		sts = append(sts, Status{
			Name:   it.Metadata.Labels[kube.LabelEngagement],
			Driver: model.DriverKata,
			State:  it.Status.Phase,
		})
	}
	return sts, nil
}

func kataResolver(host string) ([]netip.Addr, error) {
	names, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, s := range names {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}
