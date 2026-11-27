package runtime

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleBlockingOutbox struct {
	started   chan struct{}
	calls     atomic.Int64
	cancelled atomic.Bool
}

func (f *lifecycleBlockingOutbox) CleanupLifecycle(context.Context) error { return nil }
func (f *lifecycleBlockingOutbox) ProcessLifecycleDeliveryOne(ctx context.Context) (bool, error) {
	f.calls.Add(1)
	close(f.started)
	<-ctx.Done()
	f.cancelled.Store(true)
	return true, ctx.Err()
}
func TestLifecycleRuntimeCancelsAndJoinsSubmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &lifecycleBlockingOutbox{started: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); RunLifecycleOutbox(ctx, f) }()
	select {
	case <-f.started:
	case <-time.After(2 * time.Second):
		t.Fatal("submission did not begin")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not join cancelled submission")
	}
	if f.calls.Load() != 1 || !f.cancelled.Load() {
		t.Fatal("submission was retried or cancellation was not propagated")
	}
}
