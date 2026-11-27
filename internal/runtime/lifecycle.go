package runtime

import (
	"context"
	"time"
)

type lifecycleOutbox interface {
	CleanupLifecycle(context.Context) error
	ProcessLifecycleDeliveryOne(context.Context) (bool, error)
}

// RunLifecycleOutbox owns one bounded submission at a time. A terminal/unknown
// delivery is never retried; only a new approved token can create another job.
// Cancellation is propagated into the transport and joined by IdentityRuntime.
func RunLifecycleOutbox(ctx context.Context, service lifecycleOutbox) {
	if service == nil {
		return
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if e := service.CleanupLifecycle(ctx); e != nil {
			timer.Reset(time.Second)
			continue
		}
		processed, e := service.ProcessLifecycleDeliveryOne(ctx)
		delay := time.Second
		if e == nil && processed {
			delay = 25 * time.Millisecond
		}
		timer.Reset(delay)
	}
}
