package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/mailtransport"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

type emailRuntimeAuthority struct{}

func (emailRuntimeAuthority) Head(context.Context) (securityjournal.Head, error) {
	return securityjournal.Head{AuthorityID: "email_runtime_test", Epoch: 1, RecordedAt: time.Now().UTC()}, nil
}
func (emailRuntimeAuthority) Append(context.Context, securityjournal.AppendRequest) (securityjournal.Event, error) {
	return securityjournal.Event{}, errors.New("unexpected journal mutation")
}
func (emailRuntimeAuthority) Operation(context.Context, string) (securityjournal.Event, error) {
	return securityjournal.Event{}, securityjournal.ErrNotFound
}
func (emailRuntimeAuthority) Events(context.Context, securityjournal.UInt63, int) ([]securityjournal.Event, error) {
	return nil, nil
}

type interruptedRuntimeMail struct {
	started chan struct{}
	calls   atomic.Int32
}

func (s *interruptedRuntimeMail) Send(ctx context.Context, _ mailtransport.Message) (mailtransport.Result, error) {
	if s.calls.Add(1) == 1 {
		close(s.started)
	}
	<-ctx.Done()
	return mailtransport.Result{State: mailtransport.Unknown}, mailtransport.ErrUnknown
}

// This tests the actual runtime dispatch/cancel boundary with a real SQL store.
// Its fixed journal/sender are explicit doubles, not corporate SMTP or CP HA.
func TestEmailRuntimeCancellationNeverRequeuesSubmission(t *testing.T) {
	ctx := context.Background()
	store, e := sqlite.Open(t.TempDir() + "/email-worker.db")
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	hash, e := auth.HashPassword("synthetic-runtime-password", auth.DefaultArgon2idParams)
	if e != nil {
		t.Fatal(e)
	}
	user, e := store.CreateUser(ctx, domain.UserInput{Username: "email_worker_owner", PasswordHash: hash})
	if e != nil {
		t.Fatal(e)
	}
	profile := domain.SessionProfile{SecureProfile: true, LoginOrigin: "https://login.test", ManagementOrigin: "https://management.test", PortalHost: "portal.test"}
	if _, e = store.ApplySessionProfile(ctx, profile); e != nil {
		t.Fatal(e)
	}
	c := securitystate.New(store, emailRuntimeAuthority{})
	if e = c.Activate(ctx); e != nil {
		t.Fatal(e)
	}
	service, e := identity.New(store, c, &identity.Keyring{Active: "mfa_test", Keys: map[string]string{"mfa_test": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{71}, 32))}}, profile)
	if e != nil {
		t.Fatal(e)
	}
	service.WithDirectory(nil, nil)
	keys, e := identity.NewEmailKeyring("enc_test", "mac_test", map[string][]byte{"enc_test": bytes.Repeat([]byte{72}, 32)}, map[string][]byte{"mac_test": bytes.Repeat([]byte{73}, 32)})
	if e != nil {
		t.Fatal(e)
	}
	sender := &interruptedRuntimeMail{started: make(chan struct{})}
	email, e := identity.NewEmailService(service, keys, sender)
	if e != nil {
		t.Fatal(e)
	}
	defer email.Close()
	service.WithEmail(email)
	now := time.Now().UTC()
	tokenHash := auth.TokenHash("synthetic-runtime-source")
	if e = store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return identity.InsertSession(ctx, tx, domain.Session{ID: "email_worker_source", UserID: user.ID, TokenHash: tokenHash, CSRFHash: auth.TokenHash("csrf"), CreatedAt: now, ExpiresAt: now.Add(time.Hour), Audience: "login", AudienceOrigin: profile.LoginOrigin, AuthorityEpoch: 1, SecurityVersion: 1, PrimaryAt: &now, MFAAt: &now, LastSeenAt: &now})
	}); e != nil {
		t.Fatal(e)
	}
	actor := identity.EmailActor{TokenHash: tokenHash, Audience: "login", Origin: profile.LoginOrigin, SourceIP: "192.0.2.1"}
	contact, e := email.CreateContact(ctx, actor, "recipient@corp.test")
	if e != nil {
		t.Fatal(e)
	}
	flow, e := email.StartFlow(ctx, "login", profile.LoginOrigin, "flow_csrf", tokenHash, actor.SourceIP)
	if e != nil {
		t.Fatal(e)
	}
	a := identity.FlowAuth{ID: flow.View.ID, Binding: flow.Binding, CSRF: "flow_csrf", Origin: profile.LoginOrigin}
	challenge, e := email.Issue(ctx, a, identity.EmailIssue{Purpose: "verify_email", ContactID: contact.ID}, actor.SourceIP)
	if e != nil {
		t.Fatal(e)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); RunEmailOutbox(workerCtx, email) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("worker did not join")
		}
	}()
	select {
	case <-sender.started:
	case <-time.After(10 * time.Second):
		t.Fatal("worker never dispatched job")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled worker did not join")
	}
	view, e := email.Get(ctx, a, challenge.ID)
	if e != nil || view.DeliveryState != "failed" {
		t.Fatal("unknown cancellation not terminal", view.DeliveryState, e)
	}
	if yes, e := email.ProcessOne(ctx); yes || e != nil || sender.calls.Load() != 1 {
		t.Fatal("cancelled submission was requeued", yes, e)
	}
}
