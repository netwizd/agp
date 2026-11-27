package wafnative

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/repository"
)

func admissionProof(compiler string) *configuration.WAFQualification {
	q := &configuration.WAFQualification{CompilerDigest: compiler}
	q.ID = proofID(*q)
	return q
}

func TestNativeAdmissionBoundsWorkAcrossProviders(t *testing.T) {
	for _, holdingOperation := range []string{"current", "validate"} {
		t.Run(holdingOperation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			compiler := repository.Hash([]byte("admission test compiler"))
			entered, unblock, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
			result := make(chan error, 1)
			var unblockOnce sync.Once
			holder := &Provider{CompilerDigest: compiler, Clock: func(ctx context.Context) (time.Time, error) {
				close(entered)
				select {
				case <-unblock:
				case <-ctx.Done():
				}
				return time.Time{}, errors.New("test clock stopped before repository read")
			}}
			go func() {
				defer close(exited)
				if holdingOperation == "current" {
					result <- holder.Current(ctx, admissionProof(compiler))
					return
				}
				_, err := holder.ValidatePolicy(ctx, configmodel.WafPolicy{})
				result <- err
			}()
			t.Cleanup(func() {
				unblockOnce.Do(func() { close(unblock) })
				cancel()
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
					t.Error("native operation failed to release admission")
				}
			})
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("admitted operation did not reach the clock")
			}

			// Different instances share one process-wide bound. Neither rejected
			// API may enter load (whose first external action is Clock), even
			// when many callers arrive together.
			var clockCalls atomic.Int64
			other := &Provider{CompilerDigest: compiler, Clock: func(context.Context) (time.Time, error) {
				clockCalls.Add(1)
				return time.Time{}, errors.New("unexpected concurrent load")
			}}
			const callers = 24
			errorsSeen := make(chan error, callers)
			var callersDone sync.WaitGroup
			for i := 0; i < callers; i++ {
				callersDone.Add(1)
				go func(validate bool) {
					defer callersDone.Done()
					if validate {
						_, err := other.ValidatePolicy(ctx, configmodel.WafPolicy{})
						errorsSeen <- err
						return
					}
					errorsSeen <- other.Current(ctx, admissionProof(compiler))
				}(i%2 == 0)
			}
			callersDone.Wait()
			close(errorsSeen)
			for err := range errorsSeen {
				if !errors.Is(err, ErrBusy) {
					t.Errorf("concurrent work was not rejected as busy: %v", err)
				}
			}
			if got := clockCalls.Load(); got != 0 {
				t.Fatalf("rejected work entered load %d times", got)
			}

			unblockOnce.Do(func() { close(unblock) })
			if err := <-result; !errors.Is(err, repository.ErrUntrusted) {
				t.Fatalf("unexpected holder result: %v", err)
			}
			// An error must free admission; later legitimate work reaches load.
			if err := other.Current(ctx, admissionProof(compiler)); !errors.Is(err, repository.ErrUntrusted) {
				t.Fatalf("admission was not released after failure: %v", err)
			}
			if got := clockCalls.Load(); got != 1 {
				t.Fatalf("retry did not reach load exactly once: %d", got)
			}
		})
	}
}

func TestCanceledNativeWorkDoesNotConsumeAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	compiler := repository.Hash([]byte("canceled admission test compiler"))
	var clockCalls atomic.Int64
	p := &Provider{CompilerDigest: compiler, Clock: func(context.Context) (time.Time, error) {
		clockCalls.Add(1)
		return time.Time{}, errors.New("test clock stopped before repository read")
	}}
	if err := p.Current(ctx, admissionProof(compiler)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled current was not rejected: %v", err)
	}
	if _, err := p.ValidatePolicy(ctx, configmodel.WafPolicy{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled validation was not rejected: %v", err)
	}
	if got := clockCalls.Load(); got != 0 {
		t.Fatalf("canceled work entered load %d times", got)
	}
	if err := p.Current(context.Background(), admissionProof(compiler)); !errors.Is(err, repository.ErrUntrusted) {
		t.Fatalf("canceled work consumed admission: %v", err)
	}
	if got := clockCalls.Load(); got != 1 {
		t.Fatalf("live work did not reach load exactly once: %d", got)
	}
}
