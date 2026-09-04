package driver

import (
	"bytes"
	"net/netip"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/JorgeCarvalhoPT/nullbox/internal/kube"
	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
)

// This file is PURE (no build tag, no cluster): it renders the K8s manifests a
// Kata engagement applies. Fully unit-tested off-cluster.

// metadata addresses (policy keeps its own unexported copies).
const (
	kMetadataV4  = "169.254.169.254"
	kLinkLocalV4 = "169.254.0.0/16"
)

// portedCIDR is a prefix restricted to a set of ports (driver-local; policy's is
// unexported).
type portedCIDR struct {
	prefix netip.Prefix
	ports  []int
}

// --- minimal typed K8s object model (only the fields we set) ---

type objectMeta struct {
	Name      string            `yaml:"name"`
	Namespace string            `yaml:"namespace,omitempty"`
	Labels    map[string]string `yaml:"labels,omitempty"`
}

type k8sNamespace struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Metadata   objectMeta `yaml:"metadata"`
}

type capabilities struct {
	Add []string `yaml:"add"`
}
type securityContext struct {
	Capabilities capabilities `yaml:"capabilities"`
}
type resourceReqs struct {
	Requests map[string]string `yaml:"requests,omitempty"`
	Limits   map[string]string `yaml:"limits,omitempty"`
}
type volumeMount struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
	ReadOnly  bool   `yaml:"readOnly,omitempty"`
}
type emptyDir struct{}
type hostPath struct {
	Path string `yaml:"path"`
}
type volume struct {
	Name     string    `yaml:"name"`
	EmptyDir *emptyDir `yaml:"emptyDir,omitempty"`
	HostPath *hostPath `yaml:"hostPath,omitempty"`
}
type container struct {
	Name            string          `yaml:"name"`
	Image           string          `yaml:"image"`
	SecurityContext securityContext `yaml:"securityContext"`
	Resources       resourceReqs    `yaml:"resources"`
	VolumeMounts    []volumeMount   `yaml:"volumeMounts,omitempty"`
}
type podSpec struct {
	RuntimeClassName string      `yaml:"runtimeClassName"`
	Containers       []container `yaml:"containers"`
	Volumes          []volume    `yaml:"volumes,omitempty"`
}
type k8sPod struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Metadata   objectMeta `yaml:"metadata"`
	Spec       podSpec    `yaml:"spec"`
}

type labelSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}
type ipBlock struct {
	CIDR   string   `yaml:"cidr"`
	Except []string `yaml:"except,omitempty"`
}
type npPeer struct {
	IPBlock           *ipBlock       `yaml:"ipBlock,omitempty"`
	NamespaceSelector *labelSelector `yaml:"namespaceSelector,omitempty"`
	PodSelector       *labelSelector `yaml:"podSelector,omitempty"`
}
type npPort struct {
	Protocol string `yaml:"protocol"`
	Port     int    `yaml:"port,omitempty"`
}
type egressRule struct {
	To    []npPeer `yaml:"to,omitempty"`
	Ports []npPort `yaml:"ports,omitempty"`
}
type npSpec struct {
	PodSelector labelSelector `yaml:"podSelector"`
	PolicyTypes []string      `yaml:"policyTypes"`
	Egress      []egressRule  `yaml:"egress"`
}
type k8sNetworkPolicy struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Metadata   objectMeta `yaml:"metadata"`
	Spec       npSpec     `yaml:"spec"`
}

// renderManifests builds the Namespace + Pod + NetworkPolicy for an engagement,
// with resolved host addresses folded in as /32 allow rules. Pure.
func renderManifests(spec UpSpec, resolved map[string][]netip.Addr) ([]byte, error) {
	e := spec.Engagement
	name := e.Metadata.Name
	ns := kube.Namespace(name)
	labels := kube.Labels(name, "agent")
	denyMeta := e.Spec.Network.DenyMetadataEnabled()

	nsObj := k8sNamespace{
		APIVersion: "v1", Kind: "Namespace",
		Metadata: objectMeta{Name: ns, Labels: labels},
	}

	pod := k8sPod{
		APIVersion: "v1", Kind: "Pod",
		Metadata: objectMeta{Name: "agent", Namespace: ns, Labels: labels},
		Spec: podSpec{
			RuntimeClassName: kube.RuntimeClass(),
			Containers: []container{{
				Name:            "agent",
				Image:           spec.ImageRef,
				SecurityContext: securityContext{Capabilities: capabilities{Add: []string{"NET_ADMIN", "NET_RAW"}}},
				Resources: resourceReqs{
					Requests: map[string]string{"cpu": "1", "memory": "2Gi"},
					Limits:   map[string]string{"cpu": "4", "memory": "8Gi"},
				},
				VolumeMounts: []volumeMount{{Name: "docker", MountPath: "/var/lib/docker"}},
			}},
			Volumes: []volume{{Name: "docker", EmptyDir: &emptyDir{}}},
		},
	}
	// Optional read-only workspace hostPath (only meaningful if code is on the node).
	if spec.Workspace != "" {
		pod.Spec.Volumes = append(pod.Spec.Volumes, volume{Name: "workspace", HostPath: &hostPath{Path: spec.Workspace}})
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts,
			volumeMount{Name: "workspace", MountPath: "/workspace", ReadOnly: true})
	}

	np := k8sNetworkPolicy{
		APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy",
		Metadata: objectMeta{Name: "nbx-scope", Namespace: ns, Labels: labels},
		Spec: npSpec{
			// Select ALL pods in the (per-engagement) namespace, not just the
			// agent — otherwise sibling tool Job pods (component=tool) escape the
			// scope and get fail-open egress. The namespace holds only this
			// engagement's pods, so select-all is the correct, drift-proof scope.
			PodSelector: labelSelector{},
			PolicyTypes: []string{"Egress"},
			Egress:      buildEgress(spec, resolved, denyMeta),
		},
	}

	var docs [][]byte
	for _, o := range []any{nsObj, pod, np} {
		b, err := yaml.Marshal(o)
		if err != nil {
			return nil, err
		}
		docs = append(docs, b)
	}
	return bytes.Join(docs, []byte("---\n")), nil
}

// buildEgress maps the engagement scope to NetworkPolicy egress rules with the
// deny-wins carve encoded as ipBlock.except.
func buildEgress(spec UpSpec, resolved map[string][]netip.Addr, denyMeta bool) []egressRule {
	unported, ported, hosts := partitionScope(spec.Engagement.Spec.Scope.Allow)
	denies := denyPrefixes(spec.Engagement.Spec.Scope.Deny)

	var rules []egressRule

	// DNS first when the scope names hosts (mirrors the nft compiler's 53 gate).
	if len(hosts) > 0 {
		rules = append(rules, egressRule{
			To: []npPeer{{
				NamespaceSelector: &labelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
				PodSelector:       &labelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
			}},
			Ports: []npPort{{Protocol: "UDP", Port: 53}, {Protocol: "TCP", Port: 53}},
		})
	}

	// Fold the metadata /32 + link-local /16 into the deny set so they go through
	// the SAME cover/within carve as real denies — which only ever emits a
	// strict-subset except (an except == cidr is rejected by the API server).
	if denyMeta {
		denies = append(denies,
			netip.PrefixFrom(netip.MustParseAddr(kMetadataV4), 32),
			netip.MustParsePrefix(kLinkLocalV4))
	}

	for _, a := range unported {
		excepts, drop := exceptsFor(a, denies)
		if drop {
			continue
		}
		rules = append(rules, egressRule{To: []npPeer{{IPBlock: &ipBlock{CIDR: a.String(), Except: excepts}}}})
	}
	for _, pc := range ported {
		excepts, drop := exceptsFor(pc.prefix, denies)
		if drop {
			continue
		}
		var ports []npPort
		for _, p := range pc.ports {
			ports = append(ports, npPort{Protocol: "TCP", Port: p}, npPort{Protocol: "UDP", Port: p})
		}
		rules = append(rules, egressRule{To: []npPeer{{IPBlock: &ipBlock{CIDR: pc.prefix.String(), Except: excepts}}}, Ports: ports})
	}
	// Resolved host addresses as /32 allows. A /32 cannot be carved with except,
	// so DROP it entirely if a deny (or metadata) contains it — deny still wins.
	var addrs []netip.Addr
	for _, as := range resolved {
		for _, a := range as {
			if a.Is4() {
				addrs = append(addrs, a)
			}
		}
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	for _, a := range addrs {
		blocked := false
		for _, d := range denies {
			if d.Contains(a) {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		rules = append(rules, egressRule{To: []npPeer{{IPBlock: &ipBlock{CIDR: a.String() + "/32"}}}})
	}
	return rules
}

// exceptsFor computes the ipBlock.except entries for an allow prefix, and
// whether the allow rule should be dropped entirely. A deny that covers (or
// equals) the allow drops the whole rule; a deny STRICTLY within the allow
// becomes an except (K8s requires except to be a strict subset of the cidr).
func exceptsFor(a netip.Prefix, denies []netip.Prefix) (excepts []string, drop bool) {
	for _, d := range denies {
		if d.Bits() <= a.Bits() && d.Contains(a.Addr()) {
			return nil, true
		}
		if a.Bits() < d.Bits() && a.Contains(d.Addr()) {
			excepts = append(excepts, d.String())
		}
	}
	sort.Strings(excepts)
	return excepts, false
}

// renderLockdown is the Kill panic button: an additive deny-all-egress policy
// (deleting a policy would OPEN egress, so we ADD one).
func renderLockdown(name string) ([]byte, error) {
	np := k8sNetworkPolicy{
		APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy",
		Metadata: objectMeta{Name: "nbx-deny-all", Namespace: kube.Namespace(name), Labels: kube.Labels(name, "agent")},
		Spec: npSpec{
			PodSelector: labelSelector{}, // select all
			PolicyTypes: []string{"Egress"},
			Egress:      []egressRule{}, // no egress permitted
		},
	}
	return yaml.Marshal(np)
}

// --- scope partitioning (policy.partition is unexported, so re-derive here) ---

func partitionScope(allow []model.Target) (unported []netip.Prefix, ported []portedCIDR, hosts []model.Target) {
	for _, t := range allow {
		if t.CIDR != "" {
			if p, err := netip.ParsePrefix(t.CIDR); err == nil {
				p = p.Masked()
				if len(t.Ports) == 0 {
					unported = append(unported, p)
				} else {
					ported = append(ported, portedCIDR{prefix: p, ports: dedupeSortPortsInts(t.Ports)})
				}
			}
		} else if t.Host != "" {
			hosts = append(hosts, t)
		}
	}
	return unported, ported, hosts
}

func denyPrefixes(deny []model.Target) []netip.Prefix {
	var out []netip.Prefix
	for _, t := range deny {
		if t.CIDR != "" {
			if p, err := netip.ParsePrefix(t.CIDR); err == nil {
				out = append(out, p.Masked())
			}
		}
	}
	return out
}

func dedupeSortPortsInts(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}
