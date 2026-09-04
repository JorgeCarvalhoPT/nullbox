package toolrunner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/JorgeCarvalhoPT/nullbox/internal/kube"
)

func TestRenderJobShape(t *testing.T) {
	spec := ToolSpec{
		Tool: "nmap", Image: "nullbox/kali:full",
		Command: []string{"nmap"}, Args: []string{"-sS", "10.0.0.1"},
		Timeout: 30 * time.Second, Resources: Resources{CPU: "500m", Memory: "512Mi"},
		Stdin: []byte("x"),
	}
	b, err := RenderJob(spec, JobID{Engagement: "acme", Tool: "nmap", Nonce: "abc"}, "nbx-acme", kube.Labels("acme", "tool"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"runtimeClassName": "kata"`, `"restartPolicy": "Never"`, `"backoffLimit": 0`,
		`"automountServiceAccountToken": false`, `"image": "nullbox/kali:full"`,
		`"activeDeadlineSeconds": 30`, `"stdin": true`, `"stdinOnce": true`,
		"nullbox.dev/engagement", `"cpu": "500m"`, `"memory": "512Mi"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered job missing %q", want)
		}
	}
	// labels must be on BOTH job metadata and pod template (the NetworkPolicy selector)
	if strings.Count(s, "nullbox.dev/component") < 2 {
		t.Errorf("labels must appear on job metadata AND pod template; got %d", strings.Count(s, "nullbox.dev/component"))
	}
}

func TestJobNameTruncation(t *testing.T) {
	long := strings.Repeat("a", 63)
	n := jobName(JobID{Engagement: long, Tool: "nmap", Nonce: "1"})
	if len(n) > 63 {
		t.Errorf("job name = %d chars, must be <= 63", len(n))
	}
	// short names are not hashed
	if jobName(JobID{Engagement: "acme", Tool: "nmap", Nonce: "1"}) != "nbx-acme-nmap-1" {
		t.Errorf("short job name unexpected: %q", jobName(JobID{Engagement: "acme", Tool: "nmap", Nonce: "1"}))
	}
}

func TestKataRunnerRun(t *testing.T) {
	podJSON := `{"items":[{"status":{"containerStatuses":[{"state":{"terminated":{"exitCode":0,"reason":"Completed"}}}]}}]}`
	var seq []string
	r := &KataRunner{
		Engagement: "acme", Namespace: "nbx-acme", Nonce: func() string { return "abc" },
		Kubectl: func(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
			j := strings.Join(args, " ")
			seq = append(seq, j)
			switch {
			case strings.Contains(j, "get pods"):
				return []byte(podJSON), nil
			case strings.Contains(j, "logs"):
				return []byte("scan output"), nil
			default:
				return nil, nil
			}
		},
	}
	res, err := r.Run(context.Background(), ToolSpec{Tool: "nmap", Image: "nullbox/kali"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != "scan output" {
		t.Errorf("result %+v", res)
	}
	if !strings.Contains(seq[0], "apply -f -") {
		t.Errorf("first call should be apply, got %q", seq[0])
	}
	sawDelete := false
	for _, s := range seq {
		if strings.Contains(s, "delete job") {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Error("runner should delete the job after reading logs/status")
	}
}

func TestLocalRunnerArgv(t *testing.T) {
	var ran [][]string
	var stdinSeen []byte
	l := &LocalRunner{
		Runtime: "docker", Network: "nbx-acme", Name: func() string { return "c1" },
		Exec: func(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
			ran = append(ran, args)
			if len(args) > 0 && args[0] == "run" {
				stdinSeen = stdin
			}
			if len(args) > 0 && args[0] == "inspect" {
				return []byte("0 false"), nil
			}
			return nil, nil
		},
	}
	spec := ToolSpec{
		Tool: "nmap", Image: "kali", Command: []string{"nmap"}, Args: []string{"-sS"},
		Resources: Resources{CPU: "500m", Memory: "256Mi"}, Workdir: "/w", Stdin: []byte("hi"),
	}
	res, err := l.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	run := strings.Join(ran[0], " ")
	for _, want := range []string{"run", "--name c1", "--network nbx-acme", "--cpus 0.5", "--memory 256Mi", "--workdir /w", "kali", "nmap", "-sS"} {
		if !strings.Contains(run, want) {
			t.Errorf("run argv missing %q: %s", want, run)
		}
	}
	if strings.Index(run, "kali") > strings.Index(run, "-sS") {
		t.Error("image must precede command/args")
	}
	if string(stdinSeen) != "hi" {
		t.Error("stdin not piped to run")
	}
	if res.ExitCode != 0 || res.OOMKilled {
		t.Errorf("result %+v", res)
	}
}

func TestCPUCores(t *testing.T) {
	cases := map[string]string{"500m": "0.5", "2": "2", "1500m": "1.5", "": ""}
	for in, want := range cases {
		if got := cpuCores(in); got != want {
			t.Errorf("cpuCores(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeRunner struct{ res ToolResult }

func (f fakeRunner) Run(ctx context.Context, spec ToolSpec) (ToolResult, error) { return f.res, nil }

func TestBrokerValidateAndHandle(t *testing.T) {
	b := &RunnerBroker{AllowedImages: []string{"nullbox/"}, Runner: fakeRunner{res: ToolResult{Tool: "nmap"}}}
	if err := b.Validate(ToolSpec{Image: "nullbox/kali"}); err != nil {
		t.Errorf("allowed image rejected: %v", err)
	}
	if err := b.Validate(ToolSpec{Image: "evil/x"}); err != ErrImageNotAllowed {
		t.Errorf("out-of-allowlist image should be rejected, got %v", err)
	}
	if err := b.Validate(ToolSpec{}); err == nil {
		t.Error("empty image must fail")
	}
	raw, _ := EncodeSpec(ToolSpec{Tool: "nmap", Image: "nullbox/kali"})
	out, err := b.Handle(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := DecodeResult(out); res.Tool != "nmap" {
		t.Errorf("handle roundtrip lost tool: %+v", res)
	}
	// a disallowed image never reaches the runner
	bad, _ := EncodeSpec(ToolSpec{Tool: "x", Image: "evil/x"})
	if _, err := b.Handle(context.Background(), bad); err != ErrImageNotAllowed {
		t.Errorf("broker should block disallowed image, got %v", err)
	}
}

func TestBrokerImageBoundary(t *testing.T) {
	b := &RunnerBroker{AllowedImages: []string{"nullbox"}}
	if err := b.Validate(ToolSpec{Image: "nullbox/kali"}); err != nil {
		t.Errorf("nullbox/kali should match on a ref boundary: %v", err)
	}
	if err := b.Validate(ToolSpec{Image: "nullbox-evil/x"}); err != ErrImageNotAllowed {
		t.Error("a sibling repo sharing the prefix must be rejected")
	}
}
