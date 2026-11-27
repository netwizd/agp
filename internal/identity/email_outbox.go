package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netwizd/agp/internal/mailtransport"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type emailJob struct {
	id, challenge, flow, keyRef, nonce, ciphertext, state, claim string
	epoch, generation                                            uint64
	created, expires                                             time.Time
}

func emailReadJob(ctx context.Context, tx storage.IdentityTx, id string) (*emailJob, error) {
	j := &emailJob{}
	e := securitystate.One(ctx, tx, `SELECT id,challenge_id,flow_id,epoch,generation,key_ref,nonce,ciphertext,state,claim_id,created_at,expires_at FROM identity_email_outbox WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&j.id, &j.challenge, &j.flow, &j.epoch, &j.generation, &j.keyRef, &j.nonce, &j.ciphertext, &j.state, &j.claim, &j.created, &j.expires)
	})
	return j, e
}
func (s *EmailService) jobFlow(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, j *emailJob) (*flow, error) {
	if j.epoch != uint64(h.Epoch) || !s.identity.Now().Before(j.expires) {
		return nil, ErrProof
	}
	f, e := loadFlow(ctx, tx, j.flow)
	if e != nil {
		return nil, e
	}
	if f.Epoch != uint64(h.Epoch) || !s.identity.Now().Before(f.ExpiresAt) || f.Attempts >= 5 || f.State == "cancelled" || f.State == "expired" || f.State == "completed" {
		return nil, ErrProof
	}
	if f.Purpose == "activate" {
		if s.identity.invitations == nil {
			return nil, ErrLifecycleUnavailable
		}
		if e = s.identity.invitations.CheckFlowTx(ctx, tx, h, f); e != nil {
			return nil, e
		}
	} else if e = checkPrincipal(ctx, tx, f.PrincipalID, f.SecurityVersion, f.PasswordVersion); e != nil {
		return nil, e
	}
	if e = directoryCheckProjection(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); e != nil {
		return nil, e
	}
	if f.Purpose == "verify_email" {
		if e = liveSession(ctx, tx, f.SourceSessionID, f.PrincipalID, uint64(h.Epoch), s.identity.Now()); e != nil {
			return nil, e
		}
		if e = directoryCheckProjection(ctx, tx, h, f.PrincipalID, "sessions", f.SourceSessionID); e != nil {
			return nil, e
		}
	}
	return f, nil
}
func (s *EmailService) observeJob(ctx context.Context, id string) (*emailProof, error) {
	observation, e := s.identity.directoryObserve(ctx, func(tx storage.IdentityTx, h securityjournal.Head) (string, string, string, error) {
		j, e := emailReadJob(ctx, tx, id)
		if e != nil {
			return "", "", "", e
		}
		if j.state != "queued" {
			return "", "", "", ErrProof
		}
		f, e := s.jobFlow(ctx, tx, h, j)
		if e != nil {
			return "", "", "", e
		}
		return f.PrincipalID, "identity_flows", f.ID, nil
	})
	if e != nil {
		return nil, e
	}
	var sourceHash string
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		j, e := emailReadJob(ctx, tx, id)
		if e != nil {
			return e
		}
		f, e := s.jobFlow(ctx, tx, h, j)
		if e != nil {
			return e
		}
		if f.Purpose != "verify_email" {
			return nil
		}
		return securitystate.One(ctx, tx, `SELECT token_hash FROM sessions WHERE id=? AND user_id=?`, []any{f.SourceSessionID, f.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&sourceHash) })
	})
	if e != nil {
		return nil, e
	}
	var source *directoryObservation
	if sourceHash != "" {
		source, e = s.identity.directorySessionObservation(ctx, sourceHash)
		if e != nil {
			return nil, e
		}
	}
	return &emailProof{flow: observation, source: source}, nil
}

// SendQueued claims a server-selected outbox ID and invokes transport exactly
// once. No SMTP rejection or unknown result requeues the same ciphertext. The
// caller may call ProcessOne again for a different queued job.
func (s *EmailService) SendQueued(ctx context.Context, id string) error {
	if s == nil || s.sender == nil {
		return ErrEmailUnavailable
	}
	select {
	case s.sendSlots <- struct{}{}:
	case <-ctx.Done():
		return ErrEmailUnavailable
	}
	defer func() { <-s.sendSlots }()
	proof, e := s.observeJob(ctx, id)
	if e != nil {
		_ = s.failQueued(ctx, id)
		return e
	}
	var job *emailJob
	var recipient []byte
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		j, e := emailReadJob(ctx, tx, id)
		if e != nil {
			return e
		}
		if j.state != "queued" {
			return ErrProof
		}
		f, e := s.jobFlow(ctx, tx, h, j)
		if e != nil {
			return e
		}
		if _, e = s.validateFlow(ctx, tx, h, f, proof); e != nil {
			return e
		}
		c, e := s.readChallenge(ctx, tx, j.challenge)
		if e != nil {
			return e
		}
		contact, e := s.challengeCurrent(ctx, tx, h, f, c)
		if e != nil {
			return e
		}
		if j.generation != uint64(c.Generation) {
			return ErrProof
		}
		if !s.vault.has(j.keyRef, s.identity.Now()) {
			_, e = tx.Exec(ctx, `UPDATE identity_email_outbox SET state='failed' WHERE id=? AND state='queued'`, id)
			return e
		}
		recipient, e = s.address(contact)
		if e != nil {
			return e
		}
		j.claim = securitystate.ID("mail_claim")
		n, e := tx.Exec(ctx, `UPDATE identity_email_outbox SET state='sending',claim_id=? WHERE id=? AND state='queued' AND claim_id=''`, j.claim, id)
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
	defer clear(recipient)
	if job != nil {
		defer s.claims.Delete(job.claim)
	}
	if e != nil {
		_ = s.failQueued(ctx, id)
		return e
	}
	if job == nil {
		return ErrEmailUnavailable
	}
	key, e := s.vault.take(job.keyRef, s.identity.Now())
	if e != nil {
		return s.finishJob(ctx, job, "failed")
	}
	defer clear(key)
	code, e := emailOpen(key, job.nonce, job.ciphertext, emailEncoding("AGP-EMAIL-OUTBOX-v1", job.id, job.challenge, fmt.Sprint(job.epoch), fmt.Sprint(job.generation)))
	clear(key)
	if e != nil {
		_ = s.finishJob(ctx, job, "failed")
		return ErrEmailUnavailable
	}
	defer clear(code)
	if len(code) != 8 {
		_ = s.finishJob(ctx, job, "failed")
		return ErrEmailUnavailable
	}
	text := append([]byte("Код подтверждения адреса AGP: "), code...)
	text = append(text, []byte("\nСрок действия — до пяти минут. Этот код не заменяет пароль или второй фактор.\n")...)
	defer clear(text)
	sendContext, cancelSend := context.WithDeadline(ctx, job.expires)
	defer cancelSend()
	result, sendErr := s.sender.Send(sendContext, mailtransport.Message{ID: job.id, To: string(recipient), Subject: "Подтверждение адреса AGP", CreatedAt: job.created, Text: text})
	state := "failed"
	if result.State == mailtransport.Accepted && sendErr == nil {
		state = "accepted"
	} else if result.State == mailtransport.Unknown || errors.Is(sendErr, mailtransport.ErrUnknown) {
		state = "unknown"
	}
	if e = s.finishJob(ctx, job, state); e != nil {
		return e
	}
	if sendErr != nil {
		return ErrEmailUnavailable
	}
	return nil
}
func (s *EmailService) finishJob(ctx context.Context, j *emailJob, state string) error {
	// A client cancellation must not turn a completed DATA transaction into an
	// automatic retry. Best effort terminalization uses a separate short deadline.
	final, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.identity.Coordinator.Current(final, func(tx storage.IdentityTx, h securityjournal.Head) error {
		current, e := emailReadJob(final, tx, j.id)
		if e != nil {
			return e
		}
		if current.state != "sending" || current.claim != j.claim || current.epoch != j.epoch || current.generation != j.generation {
			return ErrProof
		}
		f, e := s.jobFlow(final, tx, h, current)
		if e != nil {
			state = "failed"
		} else {
			c, ce := s.readChallenge(final, tx, current.challenge)
			if ce != nil {
				state = "failed"
			} else if _, ce = s.challengeCurrent(final, tx, h, f, c); ce != nil {
				state = "failed"
			}
		}
		n, e := tx.Exec(final, `UPDATE identity_email_outbox SET state=? WHERE id=? AND state='sending' AND claim_id=? AND epoch=? AND generation=?`, state, j.id, j.claim, int64(j.epoch), int64(j.generation))
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrProof
		}
		return nil
	})
}

// failQueued only terminalizes an existing queued job; it grants no identity
// and never sends. It prevents an invalid first job starving later recipients.
func (s *EmailService) failQueued(ctx context.Context, id string) error {
	return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		j, e := emailReadJob(ctx, tx, id)
		if e != nil {
			return e
		}
		if j.state != "queued" {
			return nil
		}
		s.vault.drop(j.keyRef)
		_, e = tx.Exec(ctx, `UPDATE identity_email_outbox SET state='failed' WHERE id=? AND state='queued'`, id)
		return e
	})
}
func (s *EmailService) ProcessOne(ctx context.Context) (bool, error) {
	var id string
	e := s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM identity_email_outbox WHERE state='queued' ORDER BY created_at,id LIMIT 1`)
		if e != nil {
			return e
		}
		if len(ids) > 0 {
			id = ids[0]
		}
		return nil
	})
	if e != nil {
		return false, e
	}
	if id == "" {
		return false, nil
	}
	return true, s.SendQueued(ctx, id)
}
func (s *EmailService) dropKeys(ctx context.Context, tx storage.IdentityTx, q string, args ...any) error {
	refs, e := securitystate.Strings(ctx, tx, q, args...)
	if e != nil {
		return e
	}
	for _, ref := range refs {
		s.vault.drop(ref)
	}
	return nil
}
func (s *EmailService) cancelContact(ctx context.Context, tx storage.IdentityTx, id string) error {
	if e := s.dropKeys(ctx, tx, `SELECT o.key_ref FROM identity_email_outbox o JOIN identity_email_challenges c ON c.id=o.challenge_id WHERE c.contact_id=?`, id); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `UPDATE identity_email_outbox SET state='cancelled' WHERE challenge_id IN (SELECT id FROM identity_email_challenges WHERE contact_id=?) AND state IN ('queued','sending')`, id); e != nil {
		return e
	}
	_, e := tx.Exec(ctx, `UPDATE identity_email_challenges SET state='cancelled' WHERE contact_id=? AND state='active'`, id)
	return e
}

// CancelFlow participates in its caller's fenced transaction. Removing volatile
// keys on a later SQL rollback only denies mail; it cannot resurrect a proof.
func (s *EmailService) CancelFlow(ctx context.Context, tx storage.IdentityTx, id string) error {
	if s == nil {
		return nil
	}
	if e := s.dropKeys(ctx, tx, `SELECT key_ref FROM identity_email_outbox WHERE flow_id=?`, id); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `UPDATE identity_email_outbox SET state='cancelled' WHERE flow_id=? AND state IN ('queued','sending')`, id); e != nil {
		return e
	}
	_, e := tx.Exec(ctx, `UPDATE identity_email_challenges SET state='cancelled' WHERE flow_id=? AND state='active'`, id)
	return e
}

// Cleanup is bounded by the volatile vault's capacity. It is safe after restart:
// missing keys and interrupted sending jobs become terminal, never requeued.
func (s *EmailService) Cleanup(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.vault.sweep(s.identity.Now())
	return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error { return s.CleanupTx(ctx, tx, h) })
}

// CleanupTx only removes secrets or terminalizes jobs inside a caller-owned fenced transaction.
func (s *EmailService) CleanupTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) error {
	ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM identity_email_outbox WHERE state IN ('queued','sending') ORDER BY created_at,id LIMIT 2048`)
	if e != nil {
		return e
	}
	for _, id := range ids {
		j, e := emailReadJob(ctx, tx, id)
		if e != nil {
			return e
		}
		state := ""
		if j.epoch != uint64(h.Epoch) || !s.identity.Now().Before(j.expires) {
			state = "expired"
		} else if j.state == "sending" {
			if _, active := s.claims.Load(j.claim); !active {
				state = "failed"
			}
		} else if !s.vault.has(j.keyRef, s.identity.Now()) {
			state = "failed"
		} else {
			f, e := s.jobFlow(ctx, tx, h, j)
			if e != nil {
				state = "failed"
			} else {
				c, e := s.readChallenge(ctx, tx, j.challenge)
				if e != nil {
					state = "failed"
				} else if _, e = s.challengeCurrent(ctx, tx, h, f, c); e != nil {
					state = "failed"
				}
			}
		}
		if state != "" {
			s.vault.drop(j.keyRef)
			if _, e = tx.Exec(ctx, `UPDATE identity_email_outbox SET state=? WHERE id=? AND state IN ('queued','sending')`, state, id); e != nil {
				return e
			}
		}
	}
	_, e = tx.Exec(ctx, `UPDATE identity_email_challenges SET state='expired' WHERE state='active' AND (expires_at<=? OR epoch<>?)`, s.identity.Now(), int64(h.Epoch))
	return e
}
