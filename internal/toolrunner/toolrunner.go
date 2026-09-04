// Package toolrunner runs a pentest tool as a SIBLING of the agent — a
// Kubernetes Job in the engagement namespace (kata), or a sibling container on
// the laptop (krun/firecracker) — instead of inside a nested docker daemon.
//
// A sibling Job carries the engagement's kube.Labels, so the namespace
// NetworkPolicy the kata driver compiled from the scope selects it too: tool
// egress is scoped by the SAME rules as the agent, with no per-tool scope
// re-derivation and no privileged dockerd inside the guest.
package toolrunner

import (
	"context"
	"errors"
	"time"
)

// ToolRunner runs one tool invocation and returns its result.
type ToolRunner interface {
	Run(ctx context.Context, spec ToolSpec) (ToolResult, error)
}

// Resources are K8s-quantity CPU/memory strings (e.g. "500m", "512Mi").
type Resources struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// Mount is a named volume mounted into the tool.
type Mount struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

// ToolSpec describes one tool invocation. It crosses the guest→controller wire,
// so the broker validates it before dispatch.
type ToolSpec struct {
	Tool      string            `json:"tool"`
	Image     string            `json:"image"`
	Command   []string          `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Stdin     []byte            `json:"stdin,omitempty"`
	Workdir   string            `json:"workdir,omitempty"`
	Timeout   time.Duration     `json:"timeout,omitempty"`
	Resources Resources         `json:"resources,omitempty"`
	Mounts    []Mount           `json:"mounts,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// ToolResult is the outcome of a run.
type ToolResult struct {
	Tool      string    `json:"tool"`
	ExitCode  int       `json:"exitCode"`
	Stdout    []byte    `json:"stdout,omitempty"`
	Stderr    []byte    `json:"stderr,omitempty"`
	Started   time.Time `json:"started,omitempty"`
	Finished  time.Time `json:"finished,omitempty"`
	Ref       string    `json:"ref,omitempty"` // evidence-store path for large output
	TimedOut  bool      `json:"timedOut,omitempty"`
	OOMKilled bool      `json:"oomKilled,omitempty"`
}

var (
	// ErrTimedOut means the tool exceeded its deadline.
	ErrTimedOut = errors.New("toolrunner: tool timed out")
	// ErrOOMKilled means the tool was killed for exceeding memory.
	ErrOOMKilled = errors.New("toolrunner: tool OOM-killed")
	// ErrImageNotAllowed means the image failed the broker's allowlist.
	ErrImageNotAllowed = errors.New("toolrunner: image not in allowlist")
)
