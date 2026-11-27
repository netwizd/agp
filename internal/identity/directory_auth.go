package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// WithDirectory is startup-only. Without a trusted connector all linked
// principals fail closed; there is no local-password or stale-membership fallback.
func (s *Service) WithDirectory(providers *DirectoryService, connector *ADConnector) *Service {
	s.directory = providers
	s.directoryConnector = connector
	if s.Coordinator != nil {
		s.Coordinator.RegisterSessionGuard(CheckDirectorySessionProjection)
		s.Coordinator.RegisterSessionResolver(func(ctx context.Context, hash string, fn func(context.Context) error) error {
			return s.WithCurrentSession(ctx, hash, "management", s.Profile.ManagementOrigin, func(fresh context.Context, _ *domain.SessionContext) error { return fn(fresh) })
		})
	}
	return s
}

type DirectoryIdentityView struct {
	ID                   string                 `json:"id"`
	PrincipalID          string                 `json:"principalId"`
	ProviderID           string                 `json:"providerId"`
	ForestGUID           string                 `json:"forestGuid"`
	ObjectGUID           string                 `json:"objectGuid"`
	AuthenticatorVersion securityjournal.UInt63 `json:"authenticatorVersion"`
	Revoked              bool                   `json:"revoked"`
}
type directoryContext struct {
	IdentityID, ProviderVersionID         string
	IdentityVersion, ProviderGuardVersion securityjournal.UInt63
}
type directoryPin struct {
	identity   DirectoryIdentityView
	context    directoryContext
	document   DirectoryProviderDocument
	digest     string
	epoch      securityjournal.UInt63
	observedAt time.Time
}
type directoryObservation struct {
	pin     *directoryPin
	account *DirectoryAccount
}

func readDirectoryIdentity(ctx context.Context, tx storage.IdentityTx, principal string) (*DirectoryIdentityView, error) {
	r := &DirectoryIdentityView{}
	e := securitystate.One(ctx, tx, `SELECT id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,revoked FROM directory_identities WHERE principal_id=?`, []any{principal}, func(row storage.IdentityRows) error {
		return row.Scan(&r.ID, &r.PrincipalID, &r.ProviderID, &r.ForestGUID, &r.ObjectGUID, &r.AuthenticatorVersion, &r.Revoked)
	})
	if errors.Is(e, storage.ErrNotFound) {
		return nil, nil
	}
	return r, e
}
func directoryAuthPin(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal string) (*directoryPin, error) {
	return directoryAuthPinForTransition(ctx, tx, h, principal, nil)
}

// Only the provider materializer supplies its exact, independently fenced
// transition. Sessions and ordinary authorization never receive this exception.
func directoryAuthPinForTransition(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal string, transition *ProviderSecurityChange) (*directoryPin, error) {
	link, e := readDirectoryIdentity(ctx, tx, principal)
	if e != nil {
		return nil, e
	}
	if link == nil {
		var kind string
		e = securitystate.One(ctx, tx, `SELECT identity_kind FROM users WHERE id=?`, []any{principal}, func(r storage.IdentityRows) error { return r.Scan(&kind) })
		if errors.Is(e, storage.ErrNotFound) && principal == "" {
			return nil, nil
		}
		if e != nil {
			return nil, e
		}
		if kind != "local" {
			return nil, ErrProof
		}
		return nil, nil
	}
	if link.Revoked || !directoryUUID.MatchString(link.ObjectGUID) {
		return nil, ErrProof
	}
	var kind string
	e = securitystate.One(ctx, tx, `SELECT identity_kind FROM users WHERE id=? AND blocked_at IS NULL`, []any{principal}, func(r storage.IdentityRows) error { return r.Scan(&kind) })
	if e != nil || kind != "directory" {
		return nil, ErrProof
	}
	floor, e := securitystate.Floor(ctx, tx, principal, link.ID)
	if e != nil {
		return nil, e
	}
	if uint64(link.AuthenticatorVersion) < floor {
		return nil, ErrProof
	}
	provider, guard, e := readDirectory(ctx, tx, link.ProviderID)
	if e != nil {
		return nil, e
	}
	if !provider.Enabled || provider.Configuration == nil || provider.ForestGUID != link.ForestGUID {
		return nil, ErrProof
	}
	floor, e = securitystate.Floor(ctx, tx, provider.SecurityGuardID, provider.SecurityGuardID)
	if e != nil {
		return nil, e
	}
	if guard < floor {
		// The operation's own restrictive append precedes materialization. Its
		// historical participants must still match their freshly observed old
		// provider, while every unrelated or subsequent floor remains denying.
		if transition == nil || transition.ProviderID != provider.ID || transition.GuardID != provider.SecurityGuardID || transition.ExpectedAuthorityEpoch != h.Epoch || transition.ExpectedRowVersion != provider.Revision || uint64(transition.PreviousGuardVersion) != guard || uint64(transition.NextGuardVersion) != floor || transition.NextGuardVersion <= transition.PreviousGuardVersion {
			return nil, ErrProof
		}
	}
	d, e := directoryDocument(*provider.Configuration)
	if e != nil {
		return nil, e
	}
	return &directoryPin{identity: *link, document: d.Configuration, digest: d.ContentDigest, epoch: h.Epoch, observedAt: h.RecordedAt, context: directoryContext{IdentityID: link.ID, IdentityVersion: link.AuthenticatorVersion, ProviderVersionID: d.Configuration.Metadata.VersionID, ProviderGuardVersion: d.Configuration.Metadata.SecurityGuardVersion}}, nil
}
func directoryStoredContext(ctx context.Context, tx storage.IdentityTx, table, id string) (directoryContext, error) {
	var out directoryContext
	if table != "sessions" && table != "identity_flows" {
		return out, ErrProof
	}
	e := securitystate.One(ctx, tx, `SELECT directory_identity_id,directory_identity_version,directory_provider_version_id,directory_provider_guard_version FROM `+table+` WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&out.IdentityID, &out.IdentityVersion, &out.ProviderVersionID, &out.ProviderGuardVersion)
	})
	return out, e
}
func directoryCheckProjection(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal, table, id string) error {
	if e := CheckOIDCProjection(ctx, tx, h, principal, table, id); e != nil {
		return e
	}
	pin, e := directoryAuthPin(ctx, tx, h, principal)
	if e != nil {
		return e
	}
	stored, e := directoryStoredContext(ctx, tx, table, id)
	if e != nil {
		return e
	}
	if pin == nil {
		if stored != (directoryContext{}) {
			return ErrProof
		}
		return nil
	}
	if stored != pin.context {
		return ErrProof
	}
	return nil
}

// check executes inside the final fenced transaction. A proof is single-call
// memory, not persisted freshness evidence or a reusable positive cache.
func (o *directoryObservation) check(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal, table, id string) error {
	if e := directoryCheckProjection(ctx, tx, h, principal, table, id); e != nil {
		return e
	}
	pin, e := directoryAuthPin(ctx, tx, h, principal)
	if e != nil {
		return e
	}
	if o == nil || o.pin == nil {
		if pin != nil {
			return ErrProof
		}
		return nil
	}
	if h.RecordedAt.IsZero() || o.pin.observedAt.IsZero() || h.RecordedAt.Before(o.pin.observedAt) || h.RecordedAt.Sub(o.pin.observedAt) > 10*time.Second {
		return ErrDirectoryUnavailable
	}
	if pin == nil || pin.identity != o.pin.identity || pin.digest != o.pin.digest || pin.epoch != o.pin.epoch || h.Epoch != o.pin.epoch || pin.context != o.pin.context || o.account == nil || o.account.ObjectGUID != pin.identity.ObjectGUID || o.account.ForestGUID != pin.identity.ForestGUID {
		return ErrProof
	}
	var expires time.Time
	e = securitystate.One(ctx, tx, `SELECT expires_at FROM `+table+` WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&expires) })
	if e != nil {
		return e
	}
	if !h.RecordedAt.Before(expires) {
		return ErrExpired
	}
	return nil
}
func (s *Service) directoryObserve(ctx context.Context, subject func(storage.IdentityTx, securityjournal.Head) (string, string, string, error)) (*directoryObservation, error) {
	var pin *directoryPin
	e := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		principal, table, id, e := subject(tx, h)
		if e != nil {
			return e
		}
		if principal == "" {
			return nil
		}
		if e = directoryCheckProjection(ctx, tx, h, principal, table, id); e != nil {
			return e
		}
		pin, e = directoryAuthPin(ctx, tx, h, principal)
		return e
	})
	if e != nil {
		return nil, e
	}
	if pin == nil {
		return nil, nil
	}
	if s.directory == nil || s.directoryConnector == nil {
		return nil, ErrDirectoryUnavailable
	}
	account, e := s.directoryConnector.LiveCheck(ctx, pin.document, pin.identity.ObjectGUID)
	if e != nil {
		return nil, e
	}
	if account.ObjectGUID != pin.identity.ObjectGUID || account.ForestGUID != pin.identity.ForestGUID {
		return nil, ErrProof
	}
	return &directoryObservation{pin: pin, account: account}, nil
}
func (s *Service) directoryFlowObservation(ctx context.Context, a FlowAuth) (*directoryObservation, error) {
	return s.directoryObserve(ctx, func(tx storage.IdentityTx, h securityjournal.Head) (string, string, string, error) {
		f, e := s.checked(ctx, tx, h, a)
		if e != nil {
			return "", "", "", e
		}
		return f.PrincipalID, "identity_flows", f.ID, nil
	})
}
func (s *Service) directorySessionObservation(ctx context.Context, hash string) (*directoryObservation, error) {
	return s.directoryObserve(ctx, func(tx storage.IdentityTx, h securityjournal.Head) (string, string, string, error) {
		var principal, id string
		e := securitystate.One(ctx, tx, `SELECT s.user_id,s.id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.authority_epoch=? AND s.security_version=u.security_version AND u.blocked_at IS NULL`, []any{hash, s.Now(), int64(h.Epoch)}, func(r storage.IdentityRows) error { return r.Scan(&principal, &id) })
		return principal, "sessions", id, e
	})
}
func copyDirectoryContext(ctx context.Context, tx storage.IdentityTx, sourceTable, sourceID, targetTable, targetID string) error {
	c, e := directoryStoredContext(ctx, tx, sourceTable, sourceID)
	if e != nil {
		return e
	}
	if e = writeDirectoryContext(ctx, tx, targetTable, targetID, c); e != nil {
		return e
	}
	return CopyOIDCContext(ctx, tx, sourceTable, sourceID, targetTable, targetID)
}
func writeDirectoryContext(ctx context.Context, tx storage.IdentityTx, table, id string, c directoryContext) error {
	if table != "sessions" && table != "identity_flows" {
		return ErrProof
	}
	_, e := tx.Exec(ctx, `UPDATE `+table+` SET directory_identity_id=?,directory_identity_version=?,directory_provider_version_id=?,directory_provider_guard_version=? WHERE id=?`, c.IdentityID, int64(c.IdentityVersion), c.ProviderVersionID, int64(c.ProviderGuardVersion), id)
	return e
}
func directoryGroups(local []string, o *directoryObservation) []string {
	set := map[string]bool{}
	for _, id := range local {
		set[id] = true
	}
	if o != nil && o.account != nil {
		for _, id := range o.account.AccessGroupIDs {
			set[id] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sortDirectoryStrings(out)
	return out
}
func sortDirectoryStrings(out []string) { sort.Strings(out) }

func createDirectoryPrincipal(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, provider string, account *DirectoryAccount) (*DirectoryIdentityView, error) {
	var existing string
	e := securitystate.One(ctx, tx, `SELECT principal_id FROM directory_identities WHERE provider_id=? AND forest_guid=? AND object_guid=?`, []any{provider, account.ForestGUID, account.ObjectGUID}, func(r storage.IdentityRows) error { return r.Scan(&existing) })
	if e == nil {
		pin, e := directoryAuthPin(ctx, tx, h, existing)
		if e != nil || pin == nil {
			return nil, ErrProof
		}
		return &pin.identity, nil
	}
	if e != storage.ErrNotFound {
		return nil, e
	}
	id := securitystate.ID("usr")
	link := &DirectoryIdentityView{ID: securitystate.ID("directory_identity"), PrincipalID: id, ProviderID: provider, ForestGUID: account.ForestGUID, ObjectGUID: account.ObjectGUID, AuthenticatorVersion: 1}
	key := sha256.Sum256([]byte(provider + "\n" + account.ForestGUID + "\n" + account.ObjectGUID))
	username := "directory_" + hex.EncodeToString(key[:])
	display := account.DisplayName
	if len(display) > 4096 || !utf8.ValidString(display) {
		display = ""
	}
	_, e = tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,display_name,is_admin,identity_kind,security_version,password_version,created_at,updated_at) VALUES(?,?,'',?,FALSE,'directory',1,1,?,?)`, id, username, display, h.RecordedAt, h.RecordedAt)
	if e != nil {
		return nil, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO directory_identities(id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,revoked,created_at) VALUES(?,?,?,?,?,1,FALSE,?)`, link.ID, id, provider, account.ForestGUID, account.ObjectGUID, h.RecordedAt)
	return link, e
}
func (d *DirectoryService) ProvisionIdentity(ctx context.Context, a DirectoryActor, providerID, objectGUID string) (out *DirectoryIdentityView, err error) {
	if !configmodel.ValidID(providerID) || !directoryUUID.MatchString(objectGUID) {
		return nil, ErrDirectoryInvalid
	}
	connector, ok := d.validator.(*ADConnector)
	if !ok || connector == nil {
		return nil, ErrDirectoryUnavailable
	}
	var document DirectoryProviderDocument
	var digest string
	var epoch securityjournal.UInt63
	err = d.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, _ *directoryPrincipal) error {
		p, guard, e := readDirectory(ctx, tx, providerID)
		if e != nil {
			return e
		}
		if !p.Enabled || p.Configuration == nil {
			return ErrProof
		}
		floor, e := securitystate.Floor(ctx, tx, p.SecurityGuardID, p.SecurityGuardID)
		if e != nil {
			return e
		}
		if guard < floor {
			return ErrProof
		}
		v, e := directoryDocument(*p.Configuration)
		if e != nil {
			return e
		}
		document = v.Configuration
		digest = v.ContentDigest
		epoch = h.Epoch
		return nil
	})
	if err != nil {
		return nil, err
	}
	account, err := connector.LiveCheck(ctx, document, objectGUID)
	if err != nil {
		return nil, err
	}
	if account.ForestGUID != document.Spec.ForestGUID || account.ObjectGUID != objectGUID {
		return nil, ErrProof
	}
	err = d.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		provider, _, e := readDirectory(ctx, tx, providerID)
		if e != nil {
			return e
		}
		if !provider.Enabled || provider.Configuration == nil || h.Epoch != epoch {
			return ErrProof
		}
		v, e := directoryDocument(*provider.Configuration)
		if e != nil || v.ContentDigest != digest {
			return ErrProof
		}
		floor, e := securitystate.Floor(ctx, tx, provider.SecurityGuardID, provider.SecurityGuardID)
		if e != nil {
			return e
		}
		if uint64(provider.Configuration.Metadata.SecurityGuardVersion) < floor {
			return ErrProof
		}
		out, e = createDirectoryPrincipal(ctx, tx, h, providerID, account)
		if e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "identity.directory.principal_provisioned", p.id, map[string]any{"identityId": out.ID, "principalId": out.PrincipalID, "providerId": providerID, "objectGuid": objectGUID})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) PrimaryDirectory(ctx context.Context, a FlowAuth, providerID, username, password, sourceIP string) (out Transition, err error) {
	if s.directory == nil || s.directoryConnector == nil {
		return out, ErrDirectoryUnavailable
	}
	if !configmodel.ValidID(providerID) || username == "" || len(username) > 1024 || utf8.RuneCountInString(username) > 256 || password == "" || len(password) > 4096 || utf8.RuneCountInString(password) > 1024 {
		return out, ErrProof
	}
	var document DirectoryProviderDocument
	var digest string
	var epoch securityjournal.UInt63
	var observedAt time.Time
	var denial error
	err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.checked(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "pending_primary" {
			return ErrProof
		}
		if h.RecordedAt.IsZero() || !h.RecordedAt.Before(f.ExpiresAt) {
			return ErrExpired
		}
		observedAt = h.RecordedAt
		for _, bucket := range []string{"directory_source_" + auth.TokenHash(sourceIP), "directory_account_" + auth.TokenHash(providerID+"\n"+strings.ToLower(username))} {
			if e = limit(ctx, tx, bucket, s.Now()); e != nil {
				if errors.Is(e, ErrLimited) {
					denial = e
					return nil
				}
				return e
			}
		}
		p, guard, e := readDirectory(ctx, tx, providerID)
		if e != nil || !p.Enabled || p.Configuration == nil {
			return ErrProof
		}
		floor, e := securitystate.Floor(ctx, tx, p.SecurityGuardID, p.SecurityGuardID)
		if e != nil {
			return e
		}
		if guard < floor {
			return ErrProof
		}
		v, e := directoryDocument(*p.Configuration)
		if e != nil {
			return e
		}
		document = v.Configuration
		digest = v.ContentDigest
		epoch = h.Epoch
		return nil
	})
	if err != nil || denial != nil {
		if err != nil {
			return out, err
		}
		return out, denial
	}
	account, authenticateErr := s.directoryConnector.Authenticate(ctx, document, username, password)
	binding, bindingHash, err := auth.NewToken()
	if err != nil {
		return out, err
	}
	err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.checked(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "pending_primary" || h.Epoch != epoch || h.RecordedAt.Before(observedAt) || h.RecordedAt.Sub(observedAt) > 10*time.Second || !h.RecordedAt.Before(f.ExpiresAt) {
			return ErrProof
		}
		p, guard, e := readDirectory(ctx, tx, providerID)
		if e != nil || !p.Enabled || p.Configuration == nil {
			return ErrProof
		}
		v, e := directoryDocument(*p.Configuration)
		if e != nil || v.ContentDigest != digest {
			return ErrProof
		}
		floor, e := securitystate.Floor(ctx, tx, p.SecurityGuardID, p.SecurityGuardID)
		if e != nil {
			return e
		}
		if guard < floor {
			return ErrProof
		}
		if authenticateErr != nil {
			if errors.Is(authenticateErr, ErrProof) {
				denial = ErrProof
				return badAttempt(ctx, tx, f.ID)
			}
			return ErrDirectoryUnavailable
		}
		if account == nil || account.ForestGUID != document.Spec.ForestGUID {
			return ErrProof
		}
		var principal string
		e = securitystate.One(ctx, tx, `SELECT principal_id FROM directory_identities WHERE provider_id=? AND forest_guid=? AND object_guid=?`, []any{providerID, account.ForestGUID, account.ObjectGUID}, func(r storage.IdentityRows) error { return r.Scan(&principal) })
		if e == storage.ErrNotFound && document.Spec.Provisioning == "jit_unprivileged" && f.Audience == "login" && f.Purpose == "login" {
			link, e := createDirectoryPrincipal(ctx, tx, h, providerID, account)
			if e != nil {
				return e
			}
			principal = link.PrincipalID
		} else if e != nil {
			if e == storage.ErrNotFound {
				denial = ErrProof
				return badAttempt(ctx, tx, f.ID)
			}
			return e
		}
		pin, e := directoryAuthPin(ctx, tx, h, principal)
		if e != nil || pin == nil || pin.digest != digest {
			return ErrProof
		}
		var sv, pv uint64
		e = securitystate.One(ctx, tx, `SELECT security_version,password_version FROM users WHERE id=? AND blocked_at IS NULL AND identity_kind='directory'`, []any{principal}, func(r storage.IdentityRows) error { return r.Scan(&sv, &pv) })
		if e != nil {
			return ErrProof
		}
		if e = checkPrincipal(ctx, tx, principal, sv, pv); e != nil {
			return e
		}
		if f.Purpose == "step_up" {
			var sourcePrincipal string
			e = securitystate.One(ctx, tx, `SELECT user_id FROM sessions WHERE id=? AND revoked_at IS NULL`, []any{f.SourceSessionID}, func(r storage.IdentityRows) error { return r.Scan(&sourcePrincipal) })
			if e != nil || sourcePrincipal != principal {
				return ErrProof
			}
			if e = directoryCheckProjection(ctx, tx, h, principal, "sessions", f.SourceSessionID); e != nil {
				return e
			}
		}
		if f.Audience == "management" {
			allowed, e := managementAdmissionTx(ctx, tx, h, principal)
			if e != nil {
				return e
			}
			if !allowed {
				denial = ErrProof
				return badAttempt(ctx, tx, f.ID)
			}
		}
		next := "totp"
		var verified, revoked bool
		e = securitystate.One(ctx, tx, `SELECT verified,revoked FROM mfa_factors WHERE principal_id=?`, []any{principal}, func(r storage.IdentityRows) error { return r.Scan(&verified, &revoked) })
		if e != nil && e != storage.ErrNotFound {
			return e
		}
		factorFloor, e := securitystate.Floor(ctx, tx, principal, FactorID(principal))
		if e != nil {
			return e
		}
		if !verified || revoked {
			if factorFloor > 0 {
				next = "recovery"
			} else {
				next = "totp_enrollment"
			}
		}
		if f.Purpose == "recover" {
			next = "recovery"
		}
		newID := securitystate.ID("flow")
		_, e = tx.Exec(ctx, `UPDATE identity_flows SET id=?,principal_id=?,security_version=?,password_version=?,binding_hash=?,primary_verified=TRUE,primary_verified_at=?,oidc_authentication=FALSE,state='pending_mfa',next_step=? WHERE id=?`, newID, principal, int64(sv), int64(pv), bindingHash, s.Now(), next, f.ID)
		if e != nil {
			return e
		}
		if e = writeDirectoryContext(ctx, tx, "identity_flows", newID, pin.context); e != nil {
			return e
		}
		f.ID = newID
		f.PrincipalID = principal
		f.SecurityVersion = sv
		f.PasswordVersion = pv
		f.Primary = true
		f.PrimaryAt = sql.NullTime{Time: s.Now(), Valid: true}
		f.State = "pending_mfa"
		f.NextStep = next
		out = Transition{View: f.view(), Binding: binding}
		return securitystate.Audit(ctx, tx, "identity.directory.primary_proved", principal, map[string]any{"providerId": providerID, "identityId": pin.identity.ID, "flowId": newID})
	})
	if err != nil {
		return Transition{}, err
	}
	if denial != nil {
		return Transition{}, denial
	}
	return out, nil
}
