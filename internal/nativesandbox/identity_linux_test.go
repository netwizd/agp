//go:build linux

package nativesandbox

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestExecutionIdentityBinding(t *testing.T) {
	a, b := ExecutionProfileDigest(1001, 1001), ExecutionProfileDigest(1002, 1001)
	if a == "" || a == b || a == ProfileDigest() || a != ExecutionProfileDigest(1001, 1001) {
		t.Fatal("execution identity not bound")
	}
	for _, ids := range [][2]uint32{{0, 1001}, {1001, 0}, {^uint32(0), 1001}, {1001, ^uint32(0)}} {
		if ExecutionProfileDigest(ids[0], ids[1]) != "" {
			t.Fatal("invalid identity digest")
		}
		if _, e := NewAsUser(Tool{}, ids[0], ids[1]); !errors.Is(e, ErrUnavailable) {
			t.Fatal("invalid identity allowed", e)
		}
	}
	r := &Runner{tool: Tool{Digest: "sha256:synthetic"}, callerUID: uint32(os.Geteuid()), executionUID: 1001, executionGID: 1002}
	binding := r.Binding()
	if binding.ExecutionUID != 1001 || binding.ExecutionGID != 1002 || binding.ProfileDigest != ExecutionProfileDigest(1001, 1002) {
		t.Fatal("binding identity missing")
	}
	if os.Geteuid() != 0 {
		if _, e := NewAsUser(Tool{}, 1001, 1001); !errors.Is(e, ErrUnavailable) {
			t.Fatal("nonroot bridge constructor allowed", e)
		}
		r.rootBridge = true
		r.callerUID = 0
		if e := r.run(context.Background(), Spec{}, nil); !errors.Is(e, ErrUnavailable) {
			t.Fatal("forged root bridge allowed", e)
		}
	}
}
