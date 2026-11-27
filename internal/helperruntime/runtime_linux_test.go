//go:build linux

package helperruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/securityjournal"
)

type runtimeStore struct {
	out             []helper.ExecutionReceipt
	ack             []string
	state           helper.ExecutionState
	ackError, error error
}

func (s *runtimeStore) Outbox(context.Context) ([]helper.ExecutionReceipt, error) {
	return append([]helper.ExecutionReceipt(nil), s.out...), s.error
}
func (s *runtimeStore) Acknowledge(_ context.Context, id string) error {
	if s.ackError != nil {
		return s.ackError
	}
	s.ack = append(s.ack, id)
	s.out = s.out[1:]
	return nil
}
func (s *runtimeStore) Status(context.Context) (*helper.ExecutionState, error) {
	return &s.state, s.error
}
func (s *runtimeStore) Close() error { return nil }

type runtimeControl struct {
	recordError, captureError error
	delivered                 []helper.ExecutionReceipt
	challenges, captures      int
	query                     helper.BaselineChallenge
	captured                  helper.BaselineCapture
}

func (c *runtimeControl) ExecutionRecord(_ context.Context, r helper.ExecutionReceipt) error {
	c.delivered = append(c.delivered, r)
	return c.recordError
}
func (c *runtimeControl) ExecutionAuthorize(context.Context, helper.StartQuery) ([]byte, error) {
	return nil, ErrRuntime
}
func (c *runtimeControl) ExecutionBaselineChallenge(context.Context) (*helper.BaselineChallenge, error) {
	c.challenges++
	return &c.query, nil
}
func (c *runtimeControl) ExecutionCapture(_ context.Context, v helper.BaselineCapture) error {
	c.captures++
	c.captured = v
	return c.captureError
}

type runtimeEngine struct {
	query        helper.BaselineChallenge
	capture      helper.BaselineCapture
	recoverError error
	recoveries   int
}

func (e *runtimeEngine) Execute(context.Context, io.Reader) (*helper.ExecutionReceipt, error) {
	return nil, ErrRuntime
}
func (e *runtimeEngine) CaptureBaseline(_ context.Context, q helper.BaselineChallenge) (*helper.BaselineCapture, error) {
	e.query = q
	return &e.capture, nil
}
func (e *runtimeEngine) RecoverPending(context.Context) (*helper.ExecutionReceipt, error) {
	e.recoveries++
	return nil, e.recoverError
}

func TestOutboxKeepsExactOutcomeUntilObservedDelivery(t *testing.T) {
	receipt := helper.ExecutionReceipt{ReceiptID: "rcpt_1", TaskID: "task_1", Signature: "immutable_signed_bytes"}
	store := &runtimeStore{out: []helper.ExecutionReceipt{receipt}}
	control := &runtimeControl{recordError: errors.New("reply lost after remote commit"), query: helper.BaselineChallenge{ID: "nonce_1"}}
	engine := &runtimeEngine{capture: helper.BaselineCapture{Signature: "root_signed_capture"}}
	r := &Runtime{Store: store, Executor: engine, control: control}
	if r.sync(context.Background()) == nil || len(store.out) != 1 || len(store.ack) != 0 || control.challenges != 0 {
		t.Fatal("lost receipt reply acknowledged or captured a newer baseline")
	}
	control.recordError = nil
	store.ackError = errors.New("local fsync failure")
	if r.sync(context.Background()) == nil || len(store.out) != 1 || control.challenges != 0 {
		t.Fatal("local ACK failure lost outcome or advanced capture")
	}
	store.ackError = nil
	if err := r.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(control.delivered, []helper.ExecutionReceipt{receipt, receipt, receipt}) || !reflect.DeepEqual(store.ack, []string{"rcpt_1"}) || len(store.out) != 0 {
		t.Fatal("retry did not preserve exact durable outcome")
	}
	if control.challenges != 1 || control.captures != 1 || engine.query != control.query || control.captured != engine.capture {
		t.Fatal("capture not bound to actual challenge and engine result")
	}
}
func TestStartupRecoveryFailsBeforeLocalTransport(t *testing.T) {
	store := &runtimeStore{state: helper.ExecutionState{Attempt: &helper.ExecutionAttempt{}}}
	engine := &runtimeEngine{recoverError: errors.New("invalid ledger recovery")}
	r := &Runtime{Store: store, Executor: engine}
	if r.Run(context.Background()) != engine.recoverError || engine.recoveries != 1 {
		t.Fatal("startup admitted work before recovery")
	}
	engine.recoverError = helper.ErrPending
	if err := r.recover(context.Background()); err != nil {
		t.Fatal("contained unknown outcome should retain the engine fence", err)
	}
	store.state.Attempt = nil
	if err := r.recover(context.Background()); err != nil || engine.recoveries != 2 {
		t.Fatal("idle startup retried recovery")
	}
}
func TestRootStartupNeverInitializesFromAgentInput(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("nonroot rejection requires nonroot")
	}
	for _, f := range []func(context.Context, string) error{Initialize, StageInitial} {
		if f(context.Background(), "/tmp/nonexistent-agp-root-config") != ErrRuntime {
			t.Fatal("nonroot installer accepted")
		}
	}
	if _, err := Open("/tmp/nonexistent-agp-root-config"); err != ErrRuntime {
		t.Fatal("nonroot daemon accepted")
	}
}

type runtimeAuthority struct {
	challenge string
	head      securityjournal.Head
}

func (a *runtimeAuthority) HeadWithChallenge(_ context.Context, q string) (securityjournal.Head, error) {
	a.challenge = q
	return a.head, nil
}
func TestSourcePreservesExecutorNonceAndRechecksInstallation(t *testing.T) {
	a := &runtimeAuthority{head: securityjournal.Head{AuthorityID: "journal"}}
	calls := 0
	s := &sources{authority: a, witness: func() error { calls++; return nil }}
	b, err := s.Head(context.Background(), "same_executor_nonce")
	if err != nil || a.challenge != "same_executor_nonce" || !bytes.Contains(b, []byte("journal")) || calls != 1 {
		t.Fatal("executor challenge replaced", err)
	}
	s.witness = func() error { return ErrRuntime }
	a.challenge = ""
	if _, err = s.Head(context.Background(), "must_not_reach_network"); err != ErrRuntime || a.challenge != "" {
		t.Fatal("changed installation still used cached authority")
	}
}
