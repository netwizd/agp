package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type EmailIssue struct {
	Purpose   string `json:"purpose"`
	ContactID string `json:"contactId"`
}
type ChallengeView struct {
	ID            string                 `json:"id"`
	FlowID        string                 `json:"flowId"`
	Purpose       string                 `json:"purpose"`
	Generation    securityjournal.UInt63 `json:"generation"`
	ExpiresAt     time.Time              `json:"expiresAt"`
	ResendAfter   time.Time              `json:"resendAfter"`
	DeliveryState string                 `json:"deliveryState"`
}
type emailChallenge struct {
	ChallengeView
	principal, contact, pepper, mac, state, audience string
	contactVersion, epoch                            uint64
	attempts                                         int
	issued                                           time.Time
}
type emailProof struct{ flow, source *directoryObservation }

func (s *EmailService) observeFlow(ctx context.Context, a FlowAuth) (*emailProof, error) {
	p, e := s.identity.directoryFlowObservation(ctx, a)
	if e != nil {
		return nil, e
	}
	var hash string
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.identity.checked(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.Purpose == "verify_email" {
			return securitystate.One(ctx, tx, `SELECT token_hash FROM sessions WHERE id=? AND user_id=?`, []any{f.SourceSessionID, f.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&hash) })
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	var source *directoryObservation
	if hash != "" {
		source, e = s.identity.directorySessionObservation(ctx, hash)
		if e != nil {
			return nil, e
		}
	}
	return &emailProof{flow: p, source: source}, nil
}
func (s *EmailService) checkedFlow(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a FlowAuth, p *emailProof) (*flow, error) {
	f, e := s.identity.checked(ctx, tx, h, a)
	if e != nil {
		return nil, e
	}
	return s.validateFlow(ctx, tx, h, f, p)
}
func (s *EmailService) validateFlow(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow, p *emailProof) (*flow, error) {
	var e error
	if p == nil || f.PrincipalID == "" || (!f.Primary && f.Purpose != "activate") || f.State == "completed" {
		return nil, ErrProof
	}
	if e = p.flow.check(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); e != nil {
		return nil, e
	}
	switch f.Purpose {
	case "verify_email":
		if f.SourceSessionID == "" || !f.MFA || !f.MFAAt.Valid {
			return nil, ErrProof
		}
		var hash, audience, origin string
		e = securitystate.One(ctx, tx, `SELECT token_hash,audience,audience_origin FROM sessions WHERE id=? AND user_id=?`, []any{f.SourceSessionID, f.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&hash, &audience, &origin) })
		if e != nil || audience != f.Audience || origin != f.Origin {
			return nil, ErrProof
		}
		if e = p.source.check(ctx, tx, h, f.PrincipalID, "sessions", f.SourceSessionID); e != nil {
			return nil, e
		}
		// actor checks the private session proof in normal HTTP calls. For this
		// bound flow, the server-owned observation above is the equivalent proof.
		var primary, mfa, seen, revoked sql.NullTime
		var expiry time.Time
		var epoch, sv, pv uint64
		e = securitystate.One(ctx, tx, `SELECT s.primary_at,s.mfa_at,s.last_seen_at,s.revoked_at,s.expires_at,s.authority_epoch,s.security_version,u.password_version FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?`, []any{f.SourceSessionID}, func(r storage.IdentityRows) error {
			return r.Scan(&primary, &mfa, &seen, &revoked, &expiry, &epoch, &sv, &pv)
		})
		now := s.identity.Now()
		if e != nil || revoked.Valid || epoch != uint64(h.Epoch) || !primary.Valid || now.Before(primary.Time) || !mfa.Valid || now.Before(mfa.Time) || !seen.Valid || now.Before(seen.Time) || now.Sub(seen.Time) > 30*time.Minute || !now.Before(expiry) {
			return nil, ErrProof
		}
		if e = checkPrincipal(ctx, tx, f.PrincipalID, sv, pv); e != nil {
			return nil, e
		}
		if e = securitystate.CheckManagementSessionFloors(ctx, tx, hash); e != nil {
			return nil, e
		}
	case "activate":
		if s.identity.invitations == nil || f.Primary || f.PrimaryAt.Valid || f.MFA || f.State != "pending_mfa" || f.NextStep != "email_code" {
			return nil, ErrProof
		}
		if e = s.identity.invitations.CheckFlowTx(ctx, tx, h, f); e != nil {
			return nil, e
		}
		if _, e = s.identity.invitations.EmailContactTx(ctx, tx, h, f); e != nil {
			return nil, e
		}
	case "recover":
		if !f.Recovery {
			return nil, ErrProof
		}
	default:
		return nil, ErrProof
	}
	return f, nil
}
func (s *EmailService) readChallenge(ctx context.Context, tx storage.IdentityTx, id string) (*emailChallenge, error) {
	c := &emailChallenge{}
	e := securitystate.One(ctx, tx, `SELECT id,flow_id,purpose,audience,principal_id,contact_id,contact_version,epoch,generation,pepper_id,code_mac,state,attempts,issued_at,expires_at,resend_after FROM identity_email_challenges WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&c.ID, &c.FlowID, &c.Purpose, &c.audience, &c.principal, &c.contact, &c.contactVersion, &c.epoch, &c.Generation, &c.pepper, &c.mac, &c.state, &c.attempts, &c.issued, &c.ExpiresAt, &c.ResendAfter)
	})
	if errors.Is(e, storage.ErrNotFound) {
		return nil, ErrProof
	}
	return c, e
}
func (s *EmailService) challengeCurrent(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow, c *emailChallenge) (*emailContact, error) {
	if c.audience != f.Audience || c.FlowID != f.ID || c.principal != f.PrincipalID || c.epoch != uint64(h.Epoch) || c.state != "active" || !s.identity.Now().Before(c.ExpiresAt) || c.attempts >= 5 {
		return nil, ErrProof
	}
	var current, purpose, contact string
	var generation uint64
	e := securitystate.One(ctx, tx, `SELECT current_challenge_id,purpose,contact_id,generation FROM identity_email_flow_state WHERE flow_id=?`, []any{f.ID}, func(r storage.IdentityRows) error { return r.Scan(&current, &purpose, &contact, &generation) })
	if e != nil || current != c.ID || generation != uint64(c.Generation) || purpose != c.Purpose || contact != c.contact {
		return nil, ErrProof
	}
	if (c.Purpose == "verify_email" && f.Purpose != "verify_email") || (c.Purpose == "recovery_confirmation" && (f.Purpose != "recover" || !f.Recovery)) || (c.Purpose == "invite_confirmation" && f.Purpose != "activate") {
		return nil, ErrProof
	}
	if c.Purpose == "invite_confirmation" {
		if s.identity.invitations == nil {
			return nil, ErrLifecycleUnavailable
		}
		approved, e := s.identity.invitations.EmailContactTx(ctx, tx, h, f)
		if e != nil {
			return nil, e
		}
		if approved != c.contact {
			return nil, ErrProof
		}
	}
	ct, e := s.readContact(ctx, tx, c.contact, f.PrincipalID)
	if e != nil {
		return nil, e
	}
	if uint64(ct.AuthenticatorVersion) != c.contactVersion {
		return nil, ErrProof
	}
	if c.Purpose == "recovery_confirmation" && !ct.Verified {
		return nil, ErrProof
	}
	return ct, nil
}
func (s *EmailService) challengeView(ctx context.Context, tx storage.IdentityTx, c *emailChallenge) (ChallengeView, error) {
	out := c.ChallengeView
	var state, keyRef string
	e := securitystate.One(ctx, tx, `SELECT state,key_ref FROM identity_email_outbox WHERE challenge_id=?`, []any{c.ID}, func(r storage.IdentityRows) error { return r.Scan(&state, &keyRef) })
	if e != nil {
		return out, e
	}
	switch {
	case !s.identity.Now().Before(c.ExpiresAt) || c.state == "expired":
		out.DeliveryState = "expired"
	case c.state == "cancelled":
		out.DeliveryState = "failed"
	case state == "accepted":
		out.DeliveryState = "accepted"
	case state == "queued" && s.vault.has(keyRef, s.identity.Now()):
		out.DeliveryState = "queued"
	default:
		out.DeliveryState = "failed"
	}
	return out, nil
}
func emailChallengeMAC(key []byte, c *emailChallenge, f *flow, code string) string {
	return emailMAC(key, "AGP-EMAIL-OTP-v1", c.ID, f.ID, c.Purpose, f.Audience, f.PrincipalID, c.contact, fmt.Sprint(c.contactVersion), fmt.Sprint(c.epoch), code)
}
func emailBudget(ctx context.Context, tx storage.IdentityTx, bucket string, now time.Time, max int) error {
	var start time.Time
	var n int
	e := securitystate.One(ctx, tx, `SELECT window_start,attempts FROM identity_email_limits WHERE bucket=?`, []any{bucket}, func(r storage.IdentityRows) error { return r.Scan(&start, &n) })
	if errors.Is(e, storage.ErrNotFound) {
		_, e = tx.Exec(ctx, `INSERT INTO identity_email_limits(bucket,window_start,attempts) VALUES(?,?,1)`, bucket, now)
		return e
	}
	if e != nil {
		return e
	}
	if now.Before(start) {
		return ErrEmailUnavailable
	}
	if now.Sub(start) >= time.Hour {
		_, e = tx.Exec(ctx, `UPDATE identity_email_limits SET window_start=?,attempts=1 WHERE bucket=?`, now, bucket)
		return e
	}
	if n >= max {
		return ErrLimited
	}
	_, e = tx.Exec(ctx, `UPDATE identity_email_limits SET attempts=attempts+1 WHERE bucket=?`, bucket)
	return e
}
func (s *EmailService) Issue(ctx context.Context, a FlowAuth, in EmailIssue, sourceIP string) (ChallengeView, error) {
	var out ChallengeView
	if a.CSRF == "" || !configmodel.ValidID(in.ContactID) || (in.Purpose != "verify_email" && in.Purpose != "recovery_confirmation" && in.Purpose != "invite_confirmation") || len(sourceIP) > 256 {
		return out, ErrProof
	}
	p, e := s.observeFlow(ctx, a)
	if e != nil {
		return out, e
	}
	var createdRef string
	var oldRefs []string
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.checkedFlow(ctx, tx, h, a, p)
		if e != nil {
			return e
		}
		if f.State == "ready" && f.Purpose == "verify_email" {
			return ErrProof
		}
		if (in.Purpose != "verify_email" || f.Purpose != "verify_email") && (in.Purpose != "recovery_confirmation" || f.Purpose != "recover" || !f.Recovery) && (in.Purpose != "invite_confirmation" || f.Purpose != "activate") {
			return ErrProof
		}
		if in.Purpose == "invite_confirmation" {
			if s.identity.invitations == nil {
				return ErrLifecycleUnavailable
			}
			approved, e := s.identity.invitations.EmailContactTx(ctx, tx, h, f)
			if e != nil {
				return e
			}
			if approved != in.ContactID {
				return ErrProof
			}
		}
		c, e := s.readContact(ctx, tx, in.ContactID, f.PrincipalID)
		if e != nil {
			return e
		}
		if in.Purpose == "recovery_confirmation" && !c.Verified {
			return ErrProof
		}
		var current, oldContact, purpose string
		var generation uint64
		var count int
		e = securitystate.One(ctx, tx, `SELECT current_challenge_id,contact_id,purpose,generation,issue_count FROM identity_email_flow_state WHERE flow_id=?`, []any{f.ID}, func(r storage.IdentityRows) error {
			return r.Scan(&current, &oldContact, &purpose, &generation, &count)
		})
		if e != nil && !errors.Is(e, storage.ErrNotFound) {
			return e
		}
		if e == nil {
			if oldContact != in.ContactID || purpose != in.Purpose {
				return ErrProof
			}
			old, e := s.readChallenge(ctx, tx, current)
			if e != nil {
				return e
			}
			if old.state != "active" {
				return ErrProof
			}
			if s.identity.Now().Before(old.ResendAfter) {
				if _, e = s.challengeCurrent(ctx, tx, h, f, old); e != nil {
					return e
				}
				out, e = s.challengeView(ctx, tx, old)
				return e
			}
			if count >= 3 {
				return ErrLimited
			}
		}
		address, e := s.address(c)
		if e != nil {
			return e
		}
		defer clear(address)
		normalized := strings.ToLower(string(address))
		if _, e = emailAddress(string(address)); e != nil {
			return ErrEmailUnavailable
		}
		// Every retained immutable pepper enforces the same target budget. Rotation
		// must retain old peppers through the live code and one-hour budget window.
		now := s.identity.Now()
		for id, key := range s.keys.peppers {
			if e = emailBudget(ctx, tx, "target_"+id+"_"+emailMAC(key, "AGP-EMAIL-TARGET-v1", normalized), now, 5); e != nil {
				return e
			}
		}
		provider := "local"
		var providerID string
		e = securitystate.One(ctx, tx, `SELECT provider_id FROM directory_identities WHERE principal_id=?`, []any{f.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&providerID) })
		if e == nil {
			provider = providerID
		} else if !errors.Is(e, storage.ErrNotFound) {
			return e
		}
		for _, b := range []struct {
			key string
			max int
		}{{"source_" + auth.TokenHash(sourceIP), 30}, {"provider_" + provider, 500}, {"global", 1000}} {
			if e = emailBudget(ctx, tx, b.key, now, b.max); e != nil {
				return e
			}
		}
		expires := now.Add(5 * time.Minute)
		if f.ExpiresAt.Before(expires) {
			expires = f.ExpiresAt
		}
		code, e := emailCode()
		if e != nil {
			return e
		}
		generation++
		challenge := &emailChallenge{ChallengeView: ChallengeView{ID: securitystate.ID("email_challenge"), FlowID: f.ID, Purpose: in.Purpose, Generation: securityjournal.UInt63(generation), ExpiresAt: expires, ResendAfter: now.Add(time.Minute), DeliveryState: "queued"}, principal: f.PrincipalID, contact: c.ID, contactVersion: uint64(c.AuthenticatorVersion), epoch: uint64(h.Epoch), pepper: s.keys.activePepper, state: "active", issued: now}
		challenge.mac = emailChallengeMAC(s.keys.peppers[challenge.pepper], challenge, f, code)
		jobID := securitystate.ID("mail")
		ref, key, e := s.vault.put(now, expires)
		if e != nil {
			return e
		}
		defer clear(key)
		createdRef = ref
		nonce, ciphertext, e := emailSeal(key, []byte(code), emailEncoding("AGP-EMAIL-OUTBOX-v1", jobID, challenge.ID, fmt.Sprint(challenge.epoch), fmt.Sprint(generation)))
		if e != nil {
			return e
		}
		if current != "" {
			oldRefs, e = securitystate.Strings(ctx, tx, `SELECT key_ref FROM identity_email_outbox WHERE flow_id=?`, f.ID)
			if e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `UPDATE identity_email_challenges SET state='cancelled' WHERE flow_id=? AND state='active'`, f.ID); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `UPDATE identity_email_outbox SET state='cancelled' WHERE flow_id=? AND state IN ('queued','sending')`, f.ID); e != nil {
				return e
			}
		}
		_, e = tx.Exec(ctx, `INSERT INTO identity_email_challenges(id,flow_id,purpose,audience,principal_id,contact_id,contact_version,epoch,generation,pepper_id,code_mac,state,attempts,issued_at,expires_at,resend_after) VALUES(?,?,?,?,?,?,?,?,?,?,?,'active',0,?,?,?)`, challenge.ID, f.ID, in.Purpose, f.Audience, f.PrincipalID, c.ID, int64(c.AuthenticatorVersion), int64(h.Epoch), int64(generation), challenge.pepper, challenge.mac, now, expires, challenge.ResendAfter)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO identity_email_flow_state(flow_id,current_challenge_id,contact_id,purpose,generation,issue_count,source_key,provider_key) VALUES(?,?,?,?,?,1,?,?) ON CONFLICT(flow_id) DO UPDATE SET current_challenge_id=excluded.current_challenge_id,generation=excluded.generation,issue_count=identity_email_flow_state.issue_count+1`, f.ID, challenge.ID, c.ID, in.Purpose, int64(generation), auth.TokenHash(sourceIP), provider)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO identity_email_outbox(id,challenge_id,flow_id,epoch,generation,key_ref,nonce,ciphertext,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,'queued',?,?)`, jobID, challenge.ID, f.ID, int64(h.Epoch), int64(generation), ref, nonce, ciphertext, now, expires)
		if e != nil {
			return e
		}
		out = challenge.ChallengeView
		return securitystate.Audit(ctx, tx, "identity.email.queued", f.PrincipalID, map[string]any{"flow": f.ID, "challenge": challenge.ID, "generation": generation})
	})
	if e != nil {
		if createdRef != "" {
			s.vault.drop(createdRef)
		}
		return ChallengeView{}, e
	}
	for _, ref := range oldRefs {
		s.vault.drop(ref)
	}
	return out, nil
}
func (s *EmailService) Get(ctx context.Context, a FlowAuth, id string) (ChallengeView, error) {
	var out ChallengeView
	p, e := s.observeFlow(ctx, a)
	if e != nil {
		return out, e
	}
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.checkedFlow(ctx, tx, h, a, p)
		if e != nil {
			return e
		}
		c, e := s.readChallenge(ctx, tx, id)
		if e != nil {
			return e
		}
		if c.audience != f.Audience || c.FlowID != f.ID || c.principal != f.PrincipalID || c.epoch != uint64(h.Epoch) {
			return ErrProof
		}
		if _, e = s.readContact(ctx, tx, c.contact, f.PrincipalID); e != nil {
			return e
		}
		out, e = s.challengeView(ctx, tx, c)
		return e
	})
	return out, e
}
func (s *EmailService) Verify(ctx context.Context, a FlowAuth, id, code string) (FlowView, error) {
	var out FlowView
	if a.CSRF == "" {
		return out, ErrProof
	}
	p, e := s.observeFlow(ctx, a)
	if e != nil {
		return out, e
	}
	var denial error
	var refs []string
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.checkedFlow(ctx, tx, h, a, p)
		if e != nil {
			return e
		}
		c, e := s.readChallenge(ctx, tx, id)
		if e != nil {
			return e
		}
		contact, e := s.challengeCurrent(ctx, tx, h, f, c)
		if e != nil {
			return e
		}
		key := s.keys.peppers[c.pepper]
		if len(key) != 32 {
			return ErrEmailUnavailable
		}
		validFormat := len(code) == 8 && strings.Trim(code, "0123456789") == ""
		expected := ""
		if validFormat {
			expected = emailChallengeMAC(key, c, f, code)
		}
		if !validFormat || !emailEqual(c.mac, expected) {
			denial = ErrProof
			if _, e = tx.Exec(ctx, `UPDATE identity_email_challenges SET attempts=attempts+1 WHERE id=? AND state='active'`, c.ID); e != nil {
				return e
			}
			return badAttempt(ctx, tx, f.ID)
		}
		n, e := tx.Exec(ctx, `UPDATE identity_email_challenges SET state='consumed' WHERE id=? AND state='active' AND attempts<5`, c.ID)
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrProof
		}
		if c.Purpose == "verify_email" {
			n, e = tx.Exec(ctx, `UPDATE identity_contacts SET verified=TRUE,revision=revision+1,updated_at=? WHERE id=? AND principal_id=? AND authenticator_version=? AND revision=?`, s.identity.Now(), contact.ID, f.PrincipalID, int64(contact.AuthenticatorVersion), int64(contact.Revision))
			if e != nil {
				return e
			}
			if n != 1 {
				return ErrContactStale
			}
			if _, e = tx.Exec(ctx, `UPDATE identity_flows SET state='ready',next_step='complete' WHERE id=? AND state='pending_mfa'`, f.ID); e != nil {
				return e
			}
			f.State = "ready"
			f.NextStep = "complete"
		}
		if c.Purpose == "invite_confirmation" {
			if s.identity.invitations == nil {
				return ErrLifecycleUnavailable
			}
			if e = s.identity.invitations.ConfirmEmailTx(ctx, tx, h, f, contact.ID); e != nil {
				return e
			}
		}
		refs, e = securitystate.Strings(ctx, tx, `SELECT key_ref FROM identity_email_outbox WHERE challenge_id=?`, c.ID)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE identity_email_outbox SET state='cancelled' WHERE challenge_id=? AND state IN ('queued','sending')`, c.ID); e != nil {
			return e
		}
		out = f.view()
		return securitystate.Audit(ctx, tx, "identity.email.confirmed", f.PrincipalID, map[string]any{"flow": f.ID, "challenge": c.ID, "purpose": c.Purpose})
	})
	if e != nil {
		return out, e
	}
	for _, ref := range refs {
		s.vault.drop(ref)
	}
	return out, denial
}
func (s *EmailService) CompleteFlow(ctx context.Context, a FlowAuth) (Completion, error) {
	var out Completion
	if a.CSRF == "" {
		return out, ErrProof
	}
	p, e := s.observeFlow(ctx, a)
	if e != nil {
		return out, e
	}
	e = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.checkedFlow(ctx, tx, h, a, p)
		if e != nil {
			return e
		}
		if f.Purpose != "verify_email" || f.State != "ready" {
			return ErrProof
		}
		var id string
		if e = securitystate.One(ctx, tx, `SELECT current_challenge_id FROM identity_email_flow_state WHERE flow_id=?`, []any{f.ID}, func(r storage.IdentityRows) error { return r.Scan(&id) }); e != nil {
			return e
		}
		c, e := s.readChallenge(ctx, tx, id)
		if e != nil || c.state != "consumed" || c.FlowID != f.ID {
			return ErrProof
		}
		contact, e := s.readContact(ctx, tx, c.contact, f.PrincipalID)
		if e != nil {
			return e
		}
		if !contact.Verified || uint64(contact.AuthenticatorVersion) != c.contactVersion || c.epoch != uint64(h.Epoch) {
			return ErrProof
		}
		n, e := tx.Exec(ctx, `UPDATE identity_flows SET state='completed',next_step='none' WHERE id=? AND state='ready'`, f.ID)
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrProof
		}
		f.State = "completed"
		f.NextStep = "none"
		out.View = f.view()
		return nil
	})
	return out, e
}
