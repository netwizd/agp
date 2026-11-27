package identity

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/mail"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/mailtransport"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type EmailSender interface {
	Send(context.Context, mailtransport.Message) (mailtransport.Result, error)
}
type EmailService struct {
	identity  *Service
	keys      *EmailKeyring
	sender    EmailSender
	vault     *emailVault
	claims    sync.Map
	sendSlots chan struct{}
}
type EmailActor struct{ TokenHash, Audience, Origin, SourceIP string }
type ContactView struct {
	ID                   string                 `json:"id"`
	MaskedAddress        string                 `json:"maskedAddress"`
	Verified             bool                   `json:"verified"`
	AuthenticatorVersion securityjournal.UInt63 `json:"authenticatorVersion"`
	Revision             securityjournal.UInt63 `json:"revision"`
}
type ContactList struct {
	Items []ContactView `json:"items"`
}
type emailContact struct {
	ContactView
	principal, keyID, nonce, ciphertext string
}
type emailContactIntent struct {
	ID               string                 `json:"id"`
	Principal        string                 `json:"principal"`
	PreviousVersion  securityjournal.UInt63 `json:"previousVersion"`
	ExpectedRevision securityjournal.UInt63 `json:"expectedRevision"`
	NextVersion      securityjournal.UInt63 `json:"nextVersion"`
	KeyID            string                 `json:"keyId"`
	Nonce            string                 `json:"nonce"`
	Ciphertext       string                 `json:"ciphertext"`
	At               time.Time              `json:"at"`
}

func NewEmailService(identity *Service, keys *EmailKeyring, sender EmailSender) (*EmailService, error) {
	if identity == nil || identity.Coordinator == nil || keys == nil || sender == nil {
		return nil, ErrEmailUnavailable
	}
	// Prevent accidental installation configuration reuse of any MFA key.
	if identity.Keys != nil {
		for _, raw := range identity.Keys.Keys {
			b, e := base64.RawURLEncoding.DecodeString(raw)
			if e != nil {
				return nil, ErrEmailUnavailable
			}
			for _, set := range []map[string][]byte{keys.encryption, keys.peppers} {
				for _, key := range set {
					if emailEqual(string(key), string(b)) {
						clear(b)
						return nil, ErrEmailUnavailable
					}
				}
			}
			clear(b)
		}
	}
	s := &EmailService{identity: identity, keys: keys, sender: sender, vault: newEmailVault(1024), sendSlots: make(chan struct{}, 4)}
	identity.Coordinator.Register("email_contact_replace", s.materializeContact)
	return s, nil
}

// WithEmail is startup-only, before journal recovery or accepting requests.
func (s *Service) WithEmail(email *EmailService) *Service { s.email = email; return s }
func (s *EmailService) Close() {
	if s != nil {
		s.vault.close()
	}
}
func emailAddress(input string) (string, error) {
	if len(input) < 3 || len(input) > 254 || strings.TrimSpace(input) != input {
		return "", ErrProof
	}
	for _, r := range input {
		if r < 33 || r > 126 {
			return "", ErrProof
		}
	}
	a, e := mail.ParseAddress(input)
	if e != nil || a.Address != input || a.Name != "" || strings.Count(input, "@") != 1 || strings.ContainsAny(input, "\"\\<>(),;:") {
		return "", ErrProof
	}
	local, host, _ := strings.Cut(input, "@")
	if len(local) > 64 || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") || !strings.Contains(host, ".") || len(host) > 253 {
		return "", ErrProof
	}
	host = strings.ToLower(host)
	if _, e := netip.ParseAddr(host); e == nil {
		return "", ErrProof
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrProof
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", ErrProof
			}
		}
	}
	return local + "@" + host, nil
}
func maskEmail(address string) string {
	local, host, _ := strings.Cut(address, "@")
	return local[:1] + "***@" + host
}
func (s *EmailService) readContact(ctx context.Context, tx storage.IdentityTx, id, principal string) (*emailContact, error) {
	c := &emailContact{}
	e := securitystate.One(ctx, tx, `SELECT id,principal_id,authenticator_version,revision,key_id,nonce,ciphertext,verified FROM identity_contacts WHERE id=? AND principal_id=?`, []any{id, principal}, func(r storage.IdentityRows) error {
		return r.Scan(&c.ID, &c.principal, &c.AuthenticatorVersion, &c.Revision, &c.keyID, &c.nonce, &c.ciphertext, &c.Verified)
	})
	if errors.Is(e, storage.ErrNotFound) {
		return nil, ErrProof
	}
	if e != nil {
		return nil, e
	}
	floor, e := securitystate.Floor(ctx, tx, principal, id)
	if e != nil {
		return nil, e
	}
	if uint64(c.AuthenticatorVersion) < floor {
		return nil, ErrProof
	}
	return c, nil
}
func (s *EmailService) address(c *emailContact) ([]byte, error) {
	if s == nil || s.keys == nil {
		return nil, ErrEmailUnavailable
	}
	return emailOpen(s.keys.encryption[c.keyID], c.nonce, c.ciphertext, emailContactAAD(c.principal, c.ID, uint64(c.AuthenticatorVersion)))
}
func (s *EmailService) contactView(c *emailContact) (ContactView, error) {
	b, e := s.address(c)
	if e != nil {
		return ContactView{}, e
	}
	defer clear(b)
	a, e := emailAddress(string(b))
	if e != nil {
		return ContactView{}, ErrEmailUnavailable
	}
	out := c.ContactView
	out.MaskedAddress = maskEmail(a)
	return out, nil
}
func (s *EmailService) actor(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a EmailActor, fresh bool) (string, string, error) {
	if (a.Audience != "management" || a.Origin != s.identity.Profile.ManagementOrigin) && (a.Audience != "login" || a.Origin != s.identity.Profile.LoginOrigin) {
		return "", "", ErrProof
	}
	var id, principal, audience, origin string
	var epoch, sv, pv uint64
	var mfa, primary, seen, revoked sql.NullTime
	var expiry time.Time
	e := securitystate.One(ctx, tx, `SELECT s.id,s.user_id,s.audience,s.audience_origin,s.authority_epoch,s.security_version,u.password_version,s.primary_at,s.mfa_at,s.last_seen_at,s.revoked_at,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND u.blocked_at IS NULL`, []any{a.TokenHash}, func(r storage.IdentityRows) error {
		return r.Scan(&id, &principal, &audience, &origin, &epoch, &sv, &pv, &primary, &mfa, &seen, &revoked, &expiry)
	})
	now := s.identity.Now()
	if e != nil {
		return "", "", ErrProof
	}
	if revoked.Valid || epoch != uint64(h.Epoch) || audience != a.Audience || origin != a.Origin || !now.Before(expiry) || !mfa.Valid || now.Before(mfa.Time) || !seen.Valid || now.Before(seen.Time) || now.Sub(seen.Time) > 30*time.Minute {
		return "", "", ErrProof
	}
	if e = checkPrincipal(ctx, tx, principal, sv, pv); e != nil {
		return "", "", e
	}
	if e = CheckDirectorySessionProjection(ctx, tx, h, a.TokenHash); e != nil {
		return "", "", e
	}
	if fresh && (!emailRecent(now, primary) || !emailRecent(now, mfa)) {
		return "", "", ErrEmailReauthRequired
	}
	return principal, id, nil
}
func emailRecent(now time.Time, t sql.NullTime) bool {
	return t.Valid && !now.Before(t.Time) && now.Sub(t.Time) <= 5*time.Minute
}
func (s *EmailService) withActor(ctx context.Context, a EmailActor, fn func(context.Context) error) error {
	if s == nil || s.identity == nil {
		return ErrEmailUnavailable
	}
	return s.identity.WithCurrentSession(ctx, a.TokenHash, a.Audience, a.Origin, func(fresh context.Context, _ *domain.SessionContext) error { return fn(fresh) })
}
func (s *EmailService) Contacts(ctx context.Context, a EmailActor) (ContactList, error) {
	out := ContactList{Items: []ContactView{}}
	e := s.withActor(ctx, a, func(ctx context.Context) error {
		return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			principal, _, e := s.actor(ctx, tx, h, a, false)
			if e != nil {
				return e
			}
			ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM identity_contacts WHERE principal_id=? ORDER BY id LIMIT 21`, principal)
			if e != nil {
				return e
			}
			if len(ids) > 20 {
				return ErrEmailUnavailable
			}
			for _, id := range ids {
				c, e := s.readContact(ctx, tx, id, principal)
				if e != nil {
					return e
				}
				view, e := s.contactView(c)
				if e != nil {
					return e
				}
				out.Items = append(out.Items, view)
			}
			return nil
		})
	})
	return out, e
}
func (s *EmailService) CreateContact(ctx context.Context, a EmailActor, address string) (ContactView, error) {
	var out ContactView
	address, e := emailAddress(address)
	if e != nil {
		return out, e
	}
	e = s.withActor(ctx, a, func(ctx context.Context) error {
		return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			principal, _, e := s.actor(ctx, tx, h, a, true)
			if e != nil {
				return e
			}
			ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM identity_contacts WHERE principal_id=? LIMIT 20`, principal)
			if e != nil {
				return e
			}
			if len(ids) >= 20 {
				return ErrLimited
			}
			id := securitystate.ID("contact")
			nonce, ciphertext, e := emailSeal(s.keys.encryption[s.keys.activeEncryption], []byte(address), emailContactAAD(principal, id, 1))
			if e != nil {
				return e
			}
			now := s.identity.Now()
			if _, e = tx.Exec(ctx, `INSERT INTO identity_contacts(id,principal_id,authenticator_version,revision,key_id,nonce,ciphertext,verified,created_at,updated_at) VALUES(?,?,1,1,?,?,?,FALSE,?,?)`, id, principal, s.keys.activeEncryption, nonce, ciphertext, now, now); e != nil {
				return e
			}
			out = ContactView{ID: id, MaskedAddress: maskEmail(address), AuthenticatorVersion: 1, Revision: 1}
			return securitystate.Audit(ctx, tx, "identity.contact.created", principal, map[string]any{"contact": id})
		})
	})
	return out, e
}
func (s *EmailService) ReplaceContact(ctx context.Context, a EmailActor, id string, expected securityjournal.UInt63, address string) (ContactView, error) {
	var out ContactView
	address, e := emailAddress(address)
	if e != nil || !configmodel.ValidID(id) || expected == 0 {
		return out, ErrProof
	}
	e = s.withActor(ctx, a, func(ctx context.Context) error {
		return s.identity.Coordinator.ExecuteDynamic(ctx, "email_contact_replace", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
			principal, _, e := s.actor(ctx, tx, h, a, true)
			if e != nil {
				return nil, nil, e
			}
			c, e := s.readContact(ctx, tx, id, principal)
			if e != nil {
				return nil, nil, e
			}
			if c.Revision != expected {
				return nil, nil, ErrContactStale
			}
			if c.AuthenticatorVersion >= securityjournal.MaxUInt63 || c.Revision >= securityjournal.MaxUInt63 {
				return nil, nil, ErrEmailUnavailable
			}
			next := uint64(c.AuthenticatorVersion) + 1
			nonce, ciphertext, e := emailSeal(s.keys.encryption[s.keys.activeEncryption], []byte(address), emailContactAAD(principal, id, next))
			if e != nil {
				return nil, nil, e
			}
			intent := emailContactIntent{ID: id, Principal: principal, PreviousVersion: c.AuthenticatorVersion, ExpectedRevision: expected, NextVersion: securityjournal.UInt63(next), KeyID: s.keys.activeEncryption, Nonce: nonce, Ciphertext: ciphertext, At: s.identity.Now()}
			raw, e := json.Marshal(intent)
			out = ContactView{ID: id, MaskedAddress: maskEmail(address), AuthenticatorVersion: securityjournal.UInt63(next), Revision: expected + 1}
			return raw, []securityjournal.AppendRequest{securitystate.FloorRequest(principal, principal, id, next)}, e
		})
	})
	if e != nil {
		return ContactView{}, e
	}
	return out, nil
}
func (s *EmailService) materializeContact(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var i emailContactIntent
	if configmodel.StrictJSON(strings.NewReader(string(raw)), &i, 16<<10) != nil || i.NextVersion != i.PreviousVersion+1 || i.ExpectedRevision == 0 || !configmodel.ValidID(i.ID) || !configmodel.ValidID(i.Principal) || i.At.IsZero() {
		return ErrProof
	}
	floor, e := securitystate.Floor(ctx, tx, i.Principal, i.ID)
	if e != nil {
		return e
	}
	if floor < uint64(i.NextVersion) {
		return ErrProof
	}
	// Revalidate encrypted intent before making its address authoritative.
	b, e := emailOpen(s.keys.encryption[i.KeyID], i.Nonce, i.Ciphertext, emailContactAAD(i.Principal, i.ID, uint64(i.NextVersion)))
	if e != nil {
		return e
	}
	_, e = emailAddress(string(b))
	clear(b)
	if e != nil {
		return ErrProof
	}
	n, e := tx.Exec(ctx, `UPDATE identity_contacts SET authenticator_version=?,revision=revision+1,key_id=?,nonce=?,ciphertext=?,verified=FALSE,updated_at=? WHERE id=? AND principal_id=? AND authenticator_version=? AND revision=?`, int64(i.NextVersion), i.KeyID, i.Nonce, i.Ciphertext, i.At, i.ID, i.Principal, int64(i.PreviousVersion), int64(i.ExpectedRevision))
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrContactStale
	}
	if e = s.cancelContact(ctx, tx, i.ID); e != nil {
		return e
	}
	return securitystate.Audit(ctx, tx, "identity.contact.replaced", i.Principal, map[string]any{"contact": i.ID, "version": i.NextVersion})
}

// RegisterEmailRecovery must run before Coordinator.Recover. A missing keyring
// leaves a pending encrypted contact intent as a startup barrier, never an allow.
func RegisterEmailRecovery(c *securitystate.Coordinator) {
	c.Register("email_contact_replace", func(context.Context, storage.IdentityTx, json.RawMessage) error { return ErrEmailUnavailable })
}

// StartFlow is only verify_email. A current source
// session supplies principal, primary and MFA pins; no credential is invented.
func (s *EmailService) StartFlow(ctx context.Context, audience, origin, csrf, sourceHash, sourceIP string) (Transition, error) {
	var out Transition
	if csrf == "" || len(sourceIP) > 256 {
		return out, ErrProof
	}
	binding, bindingHash, e := auth.NewToken()
	if e != nil {
		return out, e
	}
	a := EmailActor{TokenHash: sourceHash, Audience: audience, Origin: origin, SourceIP: sourceIP}
	e = s.withActor(ctx, a, func(ctx context.Context) error {
		return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			principal, source, e := s.actor(ctx, tx, h, a, false)
			if e != nil {
				return e
			}
			for _, l := range []struct {
				key string
				max int
			}{{"email_flow_global", 1000}, {"email_flow_source_" + auth.TokenHash(sourceIP), 30}} {
				if e = limitN(ctx, tx, l.key, s.identity.Now(), l.max); e != nil {
					return e
				}
			}
			var sv, pv uint64
			var primary, mfa sql.NullTime
			e = securitystate.One(ctx, tx, `SELECT s.security_version,u.password_version,s.primary_at,s.mfa_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?`, []any{source}, func(r storage.IdentityRows) error { return r.Scan(&sv, &pv, &primary, &mfa) })
			if e != nil {
				return e
			}
			if !primary.Valid || primary.Time.After(s.identity.Now()) || !mfa.Valid {
				return ErrEmailReauthRequired
			}
			id := securitystate.ID("flow")
			expires := s.identity.Now().Add(5 * time.Minute)
			_, e = tx.Exec(ctx, `INSERT INTO identity_flows(id,purpose,audience,origin,binding_hash,csrf_hash,principal_id,security_version,password_version,epoch,state,next_step,primary_verified,mfa_verified,source_session_id,expires_at,mfa_at,primary_verified_at) VALUES(?,'verify_email',?,?,?,?,?,?,?,?,'pending_mfa','email_code',TRUE,TRUE,?,?,?,?)`, id, audience, origin, bindingHash, auth.TokenHash(csrf), principal, int64(sv), int64(pv), int64(h.Epoch), source, expires, mfa.Time, primary.Time)
			if e != nil {
				return e
			}
			if e = copyDirectoryContext(ctx, tx, "sessions", source, "identity_flows", id); e != nil {
				return e
			}
			out = Transition{View: FlowView{ID: id, Purpose: "verify_email", Audience: audience, State: "pending_mfa", NextStep: "email_code", ExpiresAt: expires, MFASatisfied: false}, Binding: binding}
			return nil
		})
	})
	return out, e
}
