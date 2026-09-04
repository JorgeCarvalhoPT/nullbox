package driver

import (
	"context"
	"strconv"
	"time"

	"github.com/JorgeCarvalhoPT/nullbox/internal/kube"
	"github.com/JorgeCarvalhoPT/nullbox/internal/toolrunner"
)

// RunnerProvider is an OPTIONAL driver capability: a driver that can run pentest
// tools as SIBLINGS of the agent (a K8s Job or a scoped sibling container)
// instead of inside a nested docker daemon in the guest. The Driver interface is
// unchanged; callers type-assert, exactly as console.Feed is kept separate.
type RunnerProvider interface {
	Runner(engagement string) (toolrunner.ToolRunner, error)
}

// Runner makes the kata driver a RunnerProvider: tools run as Jobs in the
// engagement namespace, governed by the same NetworkPolicy as the agent pod.
func (d *kataDriver) Runner(engagement string) (toolrunner.ToolRunner, error) {
	return &toolrunner.KataRunner{
		Engagement: engagement,
		Namespace:  kube.Namespace(engagement),
		Kubectl: func(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
			return d.kctl(stdin, args...)
		},
		// A unique per-run nonce so overlapping tool runs get distinct Job names.
		Nonce: func() string { return strconv.FormatInt(time.Now().UnixNano(), 36) },
	}, nil
}
