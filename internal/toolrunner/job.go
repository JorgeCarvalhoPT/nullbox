package toolrunner

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/JorgeCarvalhoPT/nullbox/internal/kube"
)

// JobID identifies one tool run: engagement + tool + a per-run nonce.
type JobID struct {
	Engagement string
	Tool       string
	Nonce      string
}

// --- minimal typed batch/v1 Job (only the fields we set), JSON-marshalled ---

type objectMeta struct {
	Name      string            `json:"name,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}
type envVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type resourceReqs struct {
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}
type volumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}
type emptyDir struct{}
type volume struct {
	Name     string    `json:"name"`
	EmptyDir *emptyDir `json:"emptyDir,omitempty"`
}
type container struct {
	Name         string        `json:"name"`
	Image        string        `json:"image"`
	Command      []string      `json:"command,omitempty"`
	Args         []string      `json:"args,omitempty"`
	WorkingDir   string        `json:"workingDir,omitempty"`
	Stdin        bool          `json:"stdin,omitempty"`
	StdinOnce    bool          `json:"stdinOnce,omitempty"`
	Env          []envVar      `json:"env,omitempty"`
	Resources    resourceReqs  `json:"resources,omitempty"`
	VolumeMounts []volumeMount `json:"volumeMounts,omitempty"`
}
type podSpec struct {
	RestartPolicy                string      `json:"restartPolicy"`
	RuntimeClassName             string      `json:"runtimeClassName"`
	AutomountServiceAccountToken *bool       `json:"automountServiceAccountToken,omitempty"`
	Containers                   []container `json:"containers"`
	Volumes                      []volume    `json:"volumes,omitempty"`
}
type podTemplate struct {
	Metadata objectMeta `json:"metadata"`
	Spec     podSpec    `json:"spec"`
}
type jobSpec struct {
	BackoffLimit            *int32      `json:"backoffLimit,omitempty"`
	ActiveDeadlineSeconds   *int64      `json:"activeDeadlineSeconds,omitempty"`
	TTLSecondsAfterFinished *int32      `json:"ttlSecondsAfterFinished,omitempty"`
	Template                podTemplate `json:"template"`
}
type jobManifest struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Metadata   objectMeta `json:"metadata"`
	Spec       jobSpec    `json:"spec"`
}

// RenderJob renders a batch/v1 Job for a tool invocation. Pure and deterministic
// (given a fixed nonce). Engagement labels always win over spec.Labels so the
// pod stays selected by the namespace NetworkPolicy.
func RenderJob(spec ToolSpec, id JobID, ns string, labels map[string]string) ([]byte, error) {
	name := jobName(id)
	lbl := map[string]string{}
	for k, v := range spec.Labels {
		lbl[k] = v
	}
	for k, v := range labels {
		lbl[k] = v
	}
	backoff := int32(0)
	ttl := int32(600)
	falsev := false
	var deadline *int64
	if spec.Timeout > 0 {
		s := int64(spec.Timeout.Seconds())
		deadline = &s
	}
	job := jobManifest{
		APIVersion: "batch/v1", Kind: "Job",
		Metadata: objectMeta{Name: name, Namespace: ns, Labels: lbl},
		Spec: jobSpec{
			BackoffLimit: &backoff, ActiveDeadlineSeconds: deadline, TTLSecondsAfterFinished: &ttl,
			Template: podTemplate{
				Metadata: objectMeta{Labels: lbl},
				Spec: podSpec{
					RestartPolicy:                "Never",
					RuntimeClassName:             kube.RuntimeClass(),
					AutomountServiceAccountToken: &falsev, // a tool needs no API access
					Containers: []container{{
						Name: "tool", Image: spec.Image, Command: spec.Command, Args: spec.Args,
						WorkingDir: spec.Workdir,
						Stdin:      len(spec.Stdin) > 0, StdinOnce: len(spec.Stdin) > 0,
						Env:          renderEnv(spec.Env),
						Resources:    renderResources(spec.Resources),
						VolumeMounts: renderMounts(spec.Mounts),
					}},
					Volumes: renderVolumes(spec.Mounts),
				},
			},
		},
	}
	return json.MarshalIndent(job, "", "  ")
}

// jobName builds a valid <=63-char DNS-1123 Job name, hash-suffixing when
// nbx-<eng>-<tool> would overflow so it stays unique.
func jobName(id JobID) string {
	base := "nbx-" + id.Engagement + "-" + id.Tool
	suf := "-" + id.Nonce
	if len(base)+len(suf) <= 63 {
		return sanitize(base) + suf
	}
	h := sha1.Sum([]byte(base))
	short := hex.EncodeToString(h[:])[:8]
	keep := 63 - len(suf) - 9
	if keep < 4 {
		keep = 4
	}
	return sanitize(base[:keep]) + "-" + short + suf
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func renderEnv(env map[string]string) []envVar {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]envVar, 0, len(keys))
	for _, k := range keys {
		out = append(out, envVar{Name: k, Value: env[k]})
	}
	return out
}

func renderResources(r Resources) resourceReqs {
	if r.CPU == "" && r.Memory == "" {
		return resourceReqs{}
	}
	m := map[string]string{}
	if r.CPU != "" {
		m["cpu"] = r.CPU
	}
	if r.Memory != "" {
		m["memory"] = r.Memory
	}
	// Set both requests and limits so the pod is not evicted mid-run.
	return resourceReqs{Requests: m, Limits: m}
}

func renderMounts(ms []Mount) []volumeMount {
	var out []volumeMount
	for _, m := range ms {
		out = append(out, volumeMount{Name: m.Name, MountPath: m.Path, ReadOnly: m.ReadOnly})
	}
	return out
}

func renderVolumes(ms []Mount) []volume {
	var out []volume
	for _, m := range ms {
		out = append(out, volume{Name: m.Name, EmptyDir: &emptyDir{}})
	}
	return out
}
