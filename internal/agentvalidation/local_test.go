package agentvalidation

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/securityjournal"
)

type localAuthority struct{ head securityjournal.Head }

func (a *localAuthority) Head(context.Context) (securityjournal.Head, error) { return a.head, nil }

func TestLocalDurableReplayAndInterruptedIntent(t *testing.T) {
	dir, e := os.MkdirTemp("/tmp", "agp-local-replay-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	in := testRequest()
	_, fp, e := normalize(in)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	h := securityjournal.Head{AuthorityID: "test_authority", Epoch: 1, RecordedAt: now}
	key := stringsWithoutPrefix(repository.Hash([]byte(in.RequestID)))
	if e = durableLocal(dir, key+".intent.json", localIntent{RequestVersion, fp, in, h}); e != nil {
		t.Fatal(e)
	}
	l := &Local{Native: &Native{}, Authority: &localAuthority{h}, ReceiptDir: dir, Collector: inventory.CollectorOptions{ProfilePath: "/unused", RuntimeRoot: "/unused"}}
	if _, e = l.Validate(context.Background(), in); !errors.Is(e, ErrPending) {
		t.Fatalf("unfinished intent did not fail closed: %v", e)
	}
	pd, _ := configmodel.Digest(in.Policy)
	out := &Result{APIVersion: ResultVersion, ID: "lvr_" + key, RequestID: in.RequestID, AuthorityEpoch: 1, RequestDigest: fp, CapabilityDigest: in.CapabilityDigest, PolicyDigest: pd, Pins: in.Pins, State: "validated", NativeSyntaxOnly: true, ExecutionLocation: "local_process", Isolation: "unprivileged_private_workspace", CreatedAt: now, RecordedAt: now}
	if e = durableLocal(dir, key+".result.json", out); e != nil {
		t.Fatal(e)
	}
	retry, e := l.Validate(context.Background(), in)
	if e != nil || !reflect.DeepEqual(*retry, *out) {
		t.Fatalf("exact durable replay changed or reexecuted: %v %+v", e, retry)
	}
	in.Mode = "detection"
	if _, e = l.Validate(context.Background(), in); !errors.Is(e, ErrConflict) {
		t.Fatalf("different content reused request ID: %v", e)
	}
	in.Mode = "blocking"
	l.Authority = &localAuthority{securityjournal.Head{AuthorityID: "test_authority", Epoch: 2, RecordedAt: now}}
	if _, e = l.Validate(context.Background(), in); !errors.Is(e, ErrStale) {
		t.Fatalf("old epoch replay accepted: %v", e)
	}
}
