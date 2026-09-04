package toolrunner

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// LocalRunner runs each tool as a sibling container on the SAME scoped network
// the guest uses, so tool egress traverses the identical host-nft gate — the
// laptop analogue of the shared namespace. Never nested inside the guest.
type LocalRunner struct {
	Runtime string // docker|podman|nerdctl; auto-detected if empty
	Network string // the engagement's scoped bridge (never host / default)
	Exec    func(ctx context.Context, stdin []byte, args ...string) ([]byte, error)
	Name    func() string // container name generator; nil => "nbx-tool-<tool>"
}

func (l *LocalRunner) runtime() string {
	if l.Runtime != "" {
		return l.Runtime
	}
	for _, rt := range []string{"docker", "podman", "nerdctl"} {
		if _, err := exec.LookPath(rt); err == nil {
			return rt
		}
	}
	return "docker"
}

func (l *LocalRunner) exec(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if l.Exec != nil {
		return l.Exec(ctx, stdin, args...)
	}
	c := exec.CommandContext(ctx, l.runtime(), args...)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	return c.CombinedOutput()
}

// Run starts the tool container, captures output, then inspects for exit code +
// OOM and removes it.
func (l *LocalRunner) Run(ctx context.Context, spec ToolSpec) (ToolResult, error) {
	cname := "nbx-tool-" + spec.Tool
	if l.Name != nil {
		cname = l.Name()
	}
	args := []string{"run", "--name", cname, "--network", l.Network}
	if c := cpuCores(spec.Resources.CPU); c != "" {
		args = append(args, "--cpus", c)
	}
	if spec.Resources.Memory != "" {
		args = append(args, "--memory", spec.Resources.Memory)
	}
	if spec.Workdir != "" {
		args = append(args, "--workdir", spec.Workdir)
	}
	args = append(args, spec.Image)
	args = append(args, spec.Command...)
	args = append(args, spec.Args...)

	res := ToolResult{Tool: spec.Tool}
	out, runErr := l.exec(ctx, spec.Stdin, args...)
	res.Stdout = out

	if insp, err := l.exec(ctx, nil, "inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", cname); err == nil {
		parseInspect(string(insp), &res)
	} else if runErr != nil {
		res.ExitCode = 1
	}
	_, _ = l.exec(ctx, nil, "rm", "-f", cname)
	return res, nil
}

// cpuCores converts a K8s CPU quantity ("500m", "2") to a docker --cpus value
// ("0.5", "2"). Returns "" for empty input.
func cpuCores(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return ""
	}
	if strings.HasSuffix(q, "m") {
		if milli, err := strconv.Atoi(strings.TrimSuffix(q, "m")); err == nil {
			return strconv.FormatFloat(float64(milli)/1000, 'f', -1, 64)
		}
	}
	return q
}

func parseInspect(s string, res *ToolResult) {
	fields := strings.Fields(s)
	if len(fields) >= 1 {
		if code, err := strconv.Atoi(fields[0]); err == nil {
			res.ExitCode = code
		}
	}
	if len(fields) >= 2 {
		res.OOMKilled = fields[1] == "true"
	}
}
