package toolrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// RunnerBroker is the controller-side trust boundary between the in-guest agent
// and the cluster/host. The guest sends a ToolSpec (holding NO cluster creds);
// the broker validates it against the engagement's capability contract (image
// allowlist, resource caps) and only then dispatches to the ToolRunner.
//
// The codec + validation are pure and unit-tested here; the vsock/unix transport
// that carries bytes between guest and controller is host-gated and lives with
// the driver.
type RunnerBroker struct {
	Runner        ToolRunner
	AllowedImages []string // image ref prefixes; empty => allow any (dev only)
}

// Handle validates and runs one JSON-encoded ToolSpec, returning a JSON ToolResult.
func (b *RunnerBroker) Handle(ctx context.Context, raw []byte) ([]byte, error) {
	spec, err := DecodeSpec(raw)
	if err != nil {
		return nil, fmt.Errorf("decode tool spec: %w", err)
	}
	if err := b.Validate(spec); err != nil {
		return nil, err
	}
	res, err := b.Runner.Run(ctx, spec)
	if err != nil {
		return nil, err
	}
	return json.Marshal(res)
}

// Validate enforces the capability contract on a ToolSpec.
func (b *RunnerBroker) Validate(spec ToolSpec) error {
	if spec.Image == "" {
		return fmt.Errorf("toolrunner: empty image")
	}
	if len(b.AllowedImages) > 0 {
		ok := false
		for _, a := range b.AllowedImages {
			if imageMatches(spec.Image, a) {
				ok = true
				break
			}
		}
		if !ok {
			return ErrImageNotAllowed
		}
	}
	return nil
}

// imageMatches requires the allowlist entry to match on a ref boundary, so a
// sibling repo ("nullbox-evil/x") does not pass on the "nullbox" prefix.
func imageMatches(image, allow string) bool {
	if image == allow {
		return true
	}
	if strings.HasSuffix(allow, "/") { // already a repo prefix
		return strings.HasPrefix(image, allow)
	}
	return strings.HasPrefix(image, allow+"/") ||
		strings.HasPrefix(image, allow+":") ||
		strings.HasPrefix(image, allow+"@")
}

// EncodeSpec / DecodeSpec / EncodeResult / DecodeResult are the guest↔controller
// wire codec (stable JSON).
func EncodeSpec(spec ToolSpec) ([]byte, error) { return json.Marshal(spec) }

func DecodeSpec(b []byte) (ToolSpec, error) {
	var s ToolSpec
	err := json.Unmarshal(b, &s)
	return s, err
}

func EncodeResult(res ToolResult) ([]byte, error) { return json.Marshal(res) }

func DecodeResult(b []byte) (ToolResult, error) {
	var r ToolResult
	err := json.Unmarshal(b, &r)
	return r, err
}
