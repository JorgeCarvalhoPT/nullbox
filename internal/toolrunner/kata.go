package toolrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/JorgeCarvalhoPT/nullbox/internal/kube"
)

// KataRunner runs each tool as a batch/v1 Job in the engagement namespace,
// governed by that namespace's NetworkPolicy. All cluster access goes through
// the injected Kubectl seam (nil is not valid — the driver wires a real one).
type KataRunner struct {
	Engagement string
	Namespace  string
	Kubectl    func(ctx context.Context, stdin []byte, args ...string) ([]byte, error)
	Nonce      func() string // nil => "1" (tests inject a fixed nonce)

	// PollInterval/MaxPolls bound the wait for the Job to terminate.
	PollInterval time.Duration
	MaxPolls     int
}

func (r *KataRunner) nonce() string {
	if r.Nonce != nil {
		return r.Nonce()
	}
	return "1"
}

// Run applies the Job, waits for its pod to terminate, collects logs + exit
// status, then deletes the Job.
func (r *KataRunner) Run(ctx context.Context, spec ToolSpec) (ToolResult, error) {
	id := JobID{Engagement: r.Engagement, Tool: spec.Tool, Nonce: r.nonce()}
	manifest, err := RenderJob(spec, id, r.Namespace, kube.Labels(r.Engagement, "tool"))
	if err != nil {
		return ToolResult{}, err
	}
	name := jobName(id)
	if out, err := r.Kubectl(ctx, manifest, "-n", r.Namespace, "apply", "-f", "-"); err != nil {
		return ToolResult{}, fmt.Errorf("apply job: %v: %s", err, string(out))
	}

	res := ToolResult{Tool: spec.Tool}
	interval := r.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	maxPolls := r.MaxPolls
	if maxPolls <= 0 {
		maxPolls = 600
	}
	terminated := false
	for i := 0; i < maxPolls; i++ {
		if ctx.Err() != nil {
			res.TimedOut = true
			break
		}
		podJSON, err := r.Kubectl(ctx, nil, "-n", r.Namespace, "get", "pods", "-l", "job-name="+name, "-o", "json")
		if err == nil && parsePodStatus(podJSON, &res) {
			terminated = true
			break
		}
		if i < maxPolls-1 {
			time.Sleep(interval)
		}
	}
	// Never report an unfinished run as a clean exit 0 — mark it timed out.
	if !terminated && !res.TimedOut {
		res.TimedOut = true
	}
	// Read logs + status BEFORE delete to avoid the ttl GC race.
	if logs, err := r.Kubectl(ctx, nil, "-n", r.Namespace, "logs", "job/"+name, "--all-containers"); err == nil {
		res.Stdout = logs
	}
	_, _ = r.Kubectl(ctx, nil, "-n", r.Namespace, "delete", "job", name, "--ignore-not-found")
	return res, nil
}

// parsePodStatus reads the first pod's terminated container state into res and
// reports whether it was terminated.
func parsePodStatus(b []byte, res *ToolResult) bool {
	var pods struct {
		Items []struct {
			Status struct {
				ContainerStatuses []struct {
					State struct {
						Terminated *struct {
							ExitCode int    `json:"exitCode"`
							Reason   string `json:"reason"`
						} `json:"terminated"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal(b, &pods) != nil || len(pods.Items) == 0 {
		return false
	}
	cs := pods.Items[0].Status.ContainerStatuses
	if len(cs) == 0 || cs[0].State.Terminated == nil {
		return false
	}
	t := cs[0].State.Terminated
	res.ExitCode = t.ExitCode
	switch t.Reason {
	case "OOMKilled":
		res.OOMKilled = true
	case "DeadlineExceeded":
		res.TimedOut = true
	}
	return true
}
