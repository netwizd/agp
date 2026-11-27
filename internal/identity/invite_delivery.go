package identity

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/mailtransport"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type inviteJob struct {
	id, token, keyRef, nonce, ciphertext, state, claim string
	epoch, generation                                  uint64
	created, expires                                   time.Time
}

func inviteReadJob(ctx context.Context, tx storage.IdentityTx, id string) (*inviteJob, error) {
	j := &inviteJob{}
	e := securitystate.One(ctx, tx, `SELECT id,token_id,epoch,generation,key_ref,nonce,ciphertext,state,claim_id,created_at,expires_at FROM identity_invite_outbox WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&j.id, &j.token, &j.epoch, &j.generation, &j.keyRef, &j.nonce, &j.ciphertext, &j.state, &j.claim, &j.created, &j.expires)
	})
	return j, e
}
func inviteDeliveryAAD(j *inviteJob) []byte {
	return emailEncoding("AGP-INVITATION-OUTBOX-v1", j.id, j.token, fmt.Sprint(j.epoch), fmt.Sprint(j.generation))
}

// QueueEmailTokenTx accepts only a server-generated email capability whose
// recipient is already pinned to encrypted contact storage. The raw capability
// is never returned or persisted outside a volatile-key AEAD payload.
func (s *InvitationService) QueueEmailTokenTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t *lifecycleToken, raw string) (InviteView, error) {
	var out InviteView
	if !s.available() || s.identity.email == nil || s.identity.email.sender == nil || t == nil || t.ProofKind != "email" || (t.Purpose != "activate" && t.Purpose != "reset_password") || !validLifecycleSecret(raw) || auth.TokenHash(raw) != t.TokenHash {
		return out, ErrLifecycleUnavailable
	}
	if e := checkUnconsumedLifecycleToken(ctx, tx, h, t); e != nil {
		return out, e
	}
	c, e := s.identity.email.readContact(ctx, tx, t.ContactID, t.PrincipalID)
	if e != nil || uint64(c.AuthenticatorVersion) != t.ContactVersion {
		return out, ErrProof
	}
	if t.Purpose == "reset_password" && !c.Verified {
		return out, ErrProof
	}
	address, e := s.identity.email.address(c)
	if e != nil {
		return out, ErrLifecycleUnavailable
	}
	defer clear(address)
	if _, e = emailAddress(string(address)); e != nil {
		return out, ErrLifecycleUnavailable
	}
	expires := h.RecordedAt.Add(5 * time.Minute)
	if expires.After(t.ExpiresAt) {
		expires = t.ExpiresAt
	}
	ref, key, e := s.vault.put(h.RecordedAt, expires)
	if e != nil {
		return out, ErrLifecycleUnavailable
	}
	defer clear(key)
	j := &inviteJob{id: securitystate.ID("invite_delivery"), token: t.ID, keyRef: ref, epoch: t.Epoch, generation: t.Generation, created: h.RecordedAt, expires: expires, state: "queued"}
	if t.Purpose == "activate" {
		j.state = "prepared"
	}
	j.nonce, j.ciphertext, e = emailSeal(key, []byte(raw), inviteDeliveryAAD(j))
	if e != nil {
		s.vault.drop(ref)
		return out, ErrLifecycleUnavailable
	}
	_, e = tx.Exec(ctx, `INSERT INTO identity_invite_outbox(id,token_id,epoch,generation,key_ref,nonce,ciphertext,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, j.id, j.token, int64(j.epoch), int64(j.generation), ref, j.nonce, j.ciphertext, j.state, j.created, j.expires)
	if e != nil {
		s.vault.drop(ref)
		return out, e
	}
	return InviteView{InviteID: t.ID, DeliveryOperationID: j.id, ExpiresAt: t.ExpiresAt}, nil
}
func (s *InvitationService) GetDelivery(ctx context.Context, a LifecycleActor, id string) (*InviteDeliveryView, error) {
	var out InviteDeliveryView
	e := s.withActor(ctx, a, func(ctx context.Context) error {
		return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			actor, e := s.identity.lifecycleActor(ctx, tx, h, a, authz.PermUsersManage, false, false)
			if e != nil {
				return e
			}
			j, e := inviteReadJob(ctx, tx, id)
			if e != nil {
				return e
			}
			t, e := readLifecycleToken(ctx, tx, j.token)
			if e != nil {
				return e
			}
			if _, e = s.identity.lifecycleTargetMetadata(ctx, tx, h, actor, t.PrincipalID); e != nil {
				return e
			}
			state := j.state
			if state == "prepared" || state == "sending" {
				state = "queued"
			}
			if state == "unknown" || state == "cancelled" {
				state = "failed"
			}
			if (state == "queued") && !h.RecordedAt.Before(j.expires) {
				state = "expired"
			}
			out = InviteDeliveryView{ID: j.id, InviteID: j.token, State: state, ExpiresAt: j.expires}
			return nil
		})
	})
	if e != nil {
		return nil, e
	}
	return &out, nil
}
func (s *InvitationService) jobCurrent(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, j *inviteJob) (*lifecycleToken, *emailContact, error) {
	if j.epoch != uint64(h.Epoch) || h.RecordedAt.IsZero() || h.RecordedAt.Before(j.created) || !h.RecordedAt.Before(j.expires) {
		return nil, nil, ErrProof
	}
	t, e := readLifecycleToken(ctx, tx, j.token)
	if e != nil {
		return nil, nil, e
	}
	if t.ReservedAt != nil || t.Generation != j.generation {
		return nil, nil, ErrProof
	}
	if e = checkUnconsumedLifecycleToken(ctx, tx, h, t); e != nil {
		return nil, nil, e
	}
	if e = s.identity.lifecycleIssuerCurrent(ctx, tx, h, t); e != nil {
		return nil, nil, e
	}
	var newer int
	if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM identity_one_time_tokens WHERE principal_id=? AND purpose=? AND generation>?`, []any{t.PrincipalID, t.Purpose, int64(t.Generation)}, func(r storage.IdentityRows) error { return r.Scan(&newer) }); e != nil {
		return nil, nil, e
	}
	if newer != 0 {
		return nil, nil, ErrProof
	}
	c, e := s.identity.email.readContact(ctx, tx, t.ContactID, t.PrincipalID)
	if e != nil {
		return nil, nil, e
	}
	if uint64(c.AuthenticatorVersion) != t.ContactVersion || (t.Purpose == "reset_password" && !c.Verified) {
		return nil, nil, ErrProof
	}
	return t, c, nil
}
func (s *InvitationService) ProcessDeliveryOne(ctx context.Context) (bool, error) {
	if !s.available() || s.identity.email == nil || s.identity.email.sender == nil {
		return false, ErrLifecycleUnavailable
	}
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	defer func() { <-s.slots }()
	var id string
	var people []string
	e := s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		e := securitystate.One(ctx, tx, `SELECT id FROM identity_invite_outbox WHERE state='queued' ORDER BY created_at,id LIMIT 1`, nil, func(r storage.IdentityRows) error { return r.Scan(&id) })
		if e != nil {
			return e
		}
		j, e := inviteReadJob(ctx, tx, id)
		if e != nil {
			return e
		}
		t, e := readLifecycleToken(ctx, tx, j.token)
		if e != nil {
			return e
		}
		people = []string{t.IssuerID, t.PrincipalID}
		return nil
	})
	if errors.Is(e, storage.ErrNotFound) {
		return false, nil
	}
	if e != nil {
		return id != "", e
	}
	fresh, e := s.identity.lifecyclePeople(ctx, people)
	if e != nil {
		_ = s.failDelivery(ctx, id, "failed")
		return true, e
	}
	ctx = fresh
	var job *inviteJob
	var address []byte
	var purpose, origin string
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		j, e := inviteReadJob(ctx, tx, id)
		if e != nil {
			return e
		}
		if j.state != "queued" {
			return ErrProof
		}
		t, c, e := s.jobCurrent(ctx, tx, h, j)
		if e != nil {
			return e
		}
		if !s.vault.has(j.keyRef, h.RecordedAt) {
			return ErrLifecycleUnavailable
		}
		address, e = s.identity.email.address(c)
		if e != nil {
			return e
		}
		if _, e = emailAddress(string(address)); e != nil {
			return ErrLifecycleUnavailable
		}
		purpose = t.Purpose
		origin = s.identity.Profile.LoginOrigin
		if origin == "" {
			origin = s.identity.Profile.ManagementOrigin
		}
		if origin == "" {
			return ErrLifecycleUnavailable
		}
		j.claim = securitystate.ID("invite_claim")
		n, e := tx.Exec(ctx, `UPDATE identity_invite_outbox SET state='sending',claim_id=? WHERE id=? AND state='queued' AND claim_id=''`, j.claim, j.id)
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrProof
		}
		s.claims.Store(j.claim, struct{}{})
		job = j
		return nil
	})
	defer clear(address)
	if e != nil {
		_ = s.failDelivery(ctx, id, "failed")
		return true, e
	}
	if job == nil {
		return true, ErrLifecycleUnavailable
	}
	defer s.claims.Delete(job.claim)
	key, e := s.vault.take(job.keyRef, s.identity.Now())
	if e != nil {
		_ = s.finishDelivery(ctx, job, "failed")
		return true, ErrLifecycleUnavailable
	}
	defer clear(key)
	raw, e := emailOpen(key, job.nonce, job.ciphertext, inviteDeliveryAAD(job))
	if e != nil {
		_ = s.finishDelivery(ctx, job, "failed")
		return true, ErrLifecycleUnavailable
	}
	defer clear(raw)
	if !validLifecycleSecret(string(raw)) {
		_ = s.finishDelivery(ctx, job, "failed")
		return true, ErrLifecycleUnavailable
	}
	// The fragment never reaches an HTTP request target or a Referer. The auth
	// landing UI removes it before starting the same-origin setup flow.
	landing := origin + "/auth-ui/activate#token=" + url.QueryEscape(string(raw))
	subject := "Приглашение AGP"
	if purpose == "reset_password" {
		landing = origin + "/auth-ui/reset-password#token=" + url.QueryEscape(string(raw))
		subject = "Восстановление пароля AGP"
	}
	text := []byte("Продолжите настройку учётной записи AGP по ссылке:\n" + landing + "\nСсылка сама по себе не является паролем или вторым фактором.\n")
	defer clear(text)
	sendCtx, cancel := context.WithDeadline(ctx, job.expires)
	defer cancel()
	result, sendErr := s.identity.email.sender.Send(sendCtx, mailtransport.Message{ID: job.id, To: string(address), Subject: subject, Text: text, CreatedAt: job.created})
	state := "failed"
	if result.State == mailtransport.Accepted && sendErr == nil {
		state = "accepted"
	} else if result.State == mailtransport.Unknown || errors.Is(sendErr, mailtransport.ErrUnknown) {
		state = "unknown"
	}
	if e = s.finishDelivery(ctx, job, state); e != nil {
		return true, e
	}
	if sendErr != nil {
		return true, ErrLifecycleUnavailable
	}
	return true, nil
}
func (s *InvitationService) finishDelivery(ctx context.Context, j *inviteJob, state string) error {
	final, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.identity.Coordinator.Current(final, func(tx storage.IdentityTx, h securityjournal.Head) error {
		n, e := tx.Exec(final, `UPDATE identity_invite_outbox SET state=? WHERE id=? AND state='sending' AND claim_id=? AND epoch=? AND generation=?`, state, j.id, j.claim, int64(j.epoch), int64(j.generation))
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrProof
		}
		return nil
	})
}
func (s *InvitationService) failDelivery(ctx context.Context, id, state string) error {
	final, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.identity.Coordinator.Current(final, func(tx storage.IdentityTx, h securityjournal.Head) error {
		j, e := inviteReadJob(final, tx, id)
		if e != nil {
			return e
		}
		if j.state != "prepared" && j.state != "queued" {
			return nil
		}
		s.vault.drop(j.keyRef)
		if !h.RecordedAt.Before(j.expires) {
			state = "expired"
		}
		_, e = tx.Exec(final, `UPDATE identity_invite_outbox SET state=? WHERE id=? AND state IN ('prepared','queued')`, state, id)
		return e
	})
}
