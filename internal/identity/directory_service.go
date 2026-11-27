package identity

import (
	"context"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// DirectoryValidator is configured at startup by the trusted connector, never
// supplied by an HTTP caller. Validation runs outside the DB writer lock.
// A successful result must prove every required check against the exact version.
type DirectoryValidator interface {
	Validate(context.Context, DirectoryProviderDocument) (DirectoryValidation, error)
}
type DirectoryValidation struct {
	ForestGUID string
	Checks     []DirectoryTestCheck
}
type DirectoryService struct {
	coordinator *securitystate.Coordinator
	origin      string
	validator   DirectoryValidator
	slots       chan struct{}
}

func NewDirectoryService(c *securitystate.Coordinator, origin string, v DirectoryValidator) *DirectoryService {
	s := &DirectoryService{coordinator: c, origin: origin, validator: v, slots: make(chan struct{}, 2)}
	if c != nil {
		RegisterDirectoryRecovery(c)
	}
	return s
}

// RegisterDirectoryRecovery must run before Coordinator.Recover at startup.
// Recovery consumes an already authorized durable intent and does not invent a
// new provider proof or require access to an operator credential.
func RegisterDirectoryRecovery(c *securitystate.Coordinator) {
	if c != nil {
		c.Register("directory_provider_change", (&DirectoryService{coordinator: c}).materializeDirectoryChange)
		c.Register("directory_identity_revoke", materializeDirectoryIdentityRevoke)
	}
}

type directoryPrincipal struct {
	id, fingerprint string
	mfa             time.Time
}

func (s *DirectoryService) actor(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a DirectoryActor, write, approve bool) (*directoryPrincipal, error) {
	if s == nil || s.origin == "" || a.Origin != s.origin || a.TokenHash == "" || h.RecordedAt.IsZero() || h.Epoch == 0 {
		return nil, storage.ErrPermissionDenied
	}
	now := h.RecordedAt.UTC()
	p := &directoryPrincipal{}
	var sv, pv int64
	q := `SELECT s.user_id,s.mfa_at,u.security_version,u.password_version FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.last_seen_at>=? AND s.last_seen_at<=? AND s.audience='management' AND s.audience_origin=? AND s.authority_epoch=? AND s.security_version=u.security_version AND u.blocked_at IS NULL AND s.mfa_at IS NOT NULL AND s.mfa_at<=? AND (s.source_session_id='' OR EXISTS(SELECT 1 FROM sessions source WHERE source.id=s.source_session_id AND source.user_id=s.user_id AND source.revoked_at IS NULL AND source.authority_epoch=s.authority_epoch AND source.security_version=u.security_version AND source.expires_at>? AND source.last_seen_at>=? AND source.last_seen_at<=?))`
	args := []any{a.TokenHash, now, now.Add(-30 * time.Minute), now, s.origin, int64(h.Epoch), now, now, now.Add(-30 * time.Minute), now}
	if write {
		q += ` AND s.mfa_at>=?`
		args = append(args, now.Add(-5*time.Minute))
	}
	err := securitystate.One(ctx, tx, q, args, func(r storage.IdentityRows) error { return r.Scan(&p.id, &p.mfa, &sv, &pv) })
	if err == storage.ErrNotFound {
		return nil, storage.ErrPermissionDenied
	}
	if err != nil {
		return nil, err
	}
	if e := CheckDirectorySessionProjection(ctx, tx, h, a.TokenHash); e != nil {
		return nil, e
	}
	p.fingerprint, err = directorySubject(ctx, tx, p.id, h, approve)
	return p, err
}
func directorySubject(ctx context.Context, tx storage.IdentityTx, id string, h securityjournal.Head, approve bool) (string, error) {
	return directorySubjectAtTransition(ctx, tx, id, h, approve, nil)
}
func directorySubjectAtTransition(ctx context.Context, tx storage.IdentityTx, id string, h securityjournal.Head, approve bool, transition *ProviderSecurityChange) (string, error) {
	epoch := h.Epoch
	var admin bool
	var sv, pv uint64
	err := securitystate.One(ctx, tx, `SELECT is_admin,security_version,password_version FROM users WHERE id=? AND blocked_at IS NULL`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&admin, &sv, &pv) })
	if err == storage.ErrNotFound {
		return "", storage.ErrPermissionDenied
	}
	if err != nil {
		return "", err
	}
	if err = checkPrincipal(ctx, tx, id, sv, pv); err != nil {
		return "", storage.ErrPermissionDenied
	}
	grants, err := securitystate.ReadEffectiveGrants(ctx, tx, h, id)
	if err != nil {
		return "", err
	}
	privileged := admin || authz.HasPermission(grants.Global, authz.PermUsersPrivilegedManage)
	canApprove := authz.HasPermission(grants.Global, authz.PermConfigApprove)
	if !privileged || (approve && !canApprove) {
		return "", storage.ErrPermissionDenied
	}
	fingerprint, e := configmodel.Digest(struct {
		ID          string
		Admin       bool
		SV, PV      uint64
		Epoch       securityjournal.UInt63
		Permissions []string
		Grants      []securitystate.EffectiveGrant
	}{id, admin, sv, pv, epoch, grants.Global, grants.Entries})
	if e != nil {
		return "", e
	}
	pin, e := directoryAuthPinForTransition(ctx, tx, h, id, transition)
	if e != nil {
		return "", e
	}
	if pin == nil {
		return fingerprint, nil
	}
	if e = directorySubjectProof(ctx, pin, h); e != nil {
		return "", e
	}
	return configmodel.Digest(struct {
		ActorFingerprint string
		Identity         DirectoryIdentityView
		ProviderDigest   string
		Context          directoryContext
	}{fingerprint, pin.identity, pin.digest, pin.context})
}
func (s *DirectoryService) current(ctx context.Context, a DirectoryActor, write, approve bool, fn func(storage.IdentityTx, securityjournal.Head, *directoryPrincipal) error) error {
	if s == nil || s.coordinator == nil {
		return ErrDirectoryUnavailable
	}
	return s.coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		p, e := s.actor(ctx, tx, h, a, write, approve)
		if e != nil {
			return e
		}
		return fn(tx, h, p)
	})
}
func directoryReason(s string) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) >= 1 && utf8.RuneCountInString(s) <= 2048 && len(s) <= 8192 && strings.TrimSpace(s) != ""
}
func (s *DirectoryService) CreateProvider(ctx context.Context, a DirectoryActor, in DirectoryCreate) (out *DirectoryProviderView, err error) {
	if !directoryReason(in.Name) || utf8.RuneCountInString(in.Name) > 128 || !directoryUUID.MatchString(in.ForestGUID) || in.ForestGUID == "00000000-0000-0000-0000-000000000000" {
		return nil, ErrDirectoryInvalid
	}
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		out = &DirectoryProviderView{ID: securitystate.ID("dir"), Name: in.Name, Revision: 1, ForestGUID: in.ForestGUID, SecurityGuardID: securitystate.ID("guard_dir")}
		_, e := tx.Exec(ctx, `INSERT INTO directory_providers(id,name,forest_guid,guard_id,row_version,guard_version,enabled,created_at) VALUES(?,?,?,?,1,0,FALSE,?)`, out.ID, in.Name, in.ForestGUID, out.SecurityGuardID, h.RecordedAt)
		if e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "identity.directory.created", p.id, map[string]any{"providerId": out.ID})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func readDirectory(ctx context.Context, tx storage.IdentityTx, id string) (*DirectoryProviderView, uint64, error) {
	if !configmodel.ValidID(id) {
		return nil, 0, ErrDirectoryInvalid
	}
	out := &DirectoryProviderView{}
	var version string
	var guard uint64
	e := securitystate.One(ctx, tx, `SELECT id,name,enabled,row_version,forest_guid,guard_id,guard_version,COALESCE(active_version_id,'') FROM directory_providers WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&out.ID, &out.Name, &out.Enabled, &out.Revision, &out.ForestGUID, &out.SecurityGuardID, &guard, &version)
	})
	if e != nil {
		return nil, 0, e
	}
	if version != "" {
		v, e := readDirectoryVersion(ctx, tx, id, version)
		if e != nil {
			return nil, 0, e
		}
		if uint64(v.Configuration.Metadata.SecurityGuardVersion) != guard || v.Configuration.Metadata.SecurityGuardID != out.SecurityGuardID || v.Configuration.Spec.ForestGUID != out.ForestGUID {
			return nil, 0, ErrDirectoryStale
		}
		out.Configuration = &v.Configuration
	}
	return out, guard, nil
}
func readDirectoryVersion(ctx context.Context, tx storage.IdentityTx, id, version string) (*DirectoryVersionView, error) {
	if !configmodel.ValidID(id) || !configmodel.ValidID(version) {
		return nil, ErrDirectoryInvalid
	}
	var raw, digest string
	e := securitystate.One(ctx, tx, `SELECT canonical_json,content_digest FROM directory_provider_versions WHERE provider_id=? AND id=?`, []any{id, version}, func(r storage.IdentityRows) error { return r.Scan(&raw, &digest) })
	if e != nil {
		return nil, e
	}
	d, e := ParseDirectoryProvider(strings.NewReader(raw))
	if e != nil {
		return nil, ErrDirectoryStale
	}
	v, e := directoryDocument(*d)
	if e != nil || v.ContentDigest != digest || v.Configuration.Metadata.ID != id || v.Configuration.Metadata.VersionID != version {
		return nil, ErrDirectoryStale
	}
	canonical, e := configmodel.CanonicalJSON(d)
	if e != nil || string(canonical) != raw {
		return nil, ErrDirectoryStale
	}
	return v, nil
}
func (s *DirectoryService) GetProvider(ctx context.Context, a DirectoryActor, id string) (out *DirectoryProviderView, err error) {
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		var e error
		out, _, e = readDirectory(ctx, tx, id)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *DirectoryService) ListProviders(ctx context.Context, a DirectoryActor, limit int, cursor string) (out DirectoryProviderPage, err error) {
	if limit < 1 || limit > 200 || (cursor != "" && !configmodel.ValidID(cursor)) {
		return out, ErrDirectoryInvalid
	}
	out.Items = []DirectoryProviderView{}
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM directory_providers WHERE id>? ORDER BY id LIMIT ?`, cursor, limit+1)
		if e != nil {
			return e
		}
		// Keep a whole page below the frontend's fixed 2 MiB decode budget.
		// One closed document is at most 1 MiB; fixed provider metadata leaves
		// enough room for at least one item, so pagination always progresses.
		const pageBudget = 3 * (1 << 19)
		used := 256 // envelope, commas and cursor
		for i, id := range ids {
			if i == limit {
				out.NextCursor = out.Items[len(out.Items)-1].ID
				break
			}
			v, _, e := readDirectory(ctx, tx, id)
			if e != nil {
				return e
			}
			raw, e := json.Marshal(v)
			if e != nil {
				return e
			}
			if used+len(raw)+1 > pageBudget {
				if len(out.Items) == 0 {
					return ErrDirectoryInvalid
				}
				out.NextCursor = out.Items[len(out.Items)-1].ID
				break
			}
			used += len(raw) + 1
			out.Items = append(out.Items, *v)
		}
		return nil
	})
	if err != nil {
		return DirectoryProviderPage{}, err
	}
	return out, nil
}
func (s *DirectoryService) GetVersion(ctx context.Context, a DirectoryActor, id, version string) (out *DirectoryVersionView, err error) {
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		var e error
		out, e = readDirectoryVersion(ctx, tx, id, version)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *DirectoryService) ProposeVersion(ctx context.Context, a DirectoryActor, id string, expected securityjournal.UInt63, in DirectoryProviderDocument) (out *DirectoryVersionView, err error) {
	out, err = directoryDocument(in)
	if err != nil {
		return nil, err
	}
	if out.Configuration.Metadata.ID != id || expected == 0 || expected >= securityjournal.MaxUInt63 {
		return nil, ErrDirectoryInvalid
	}
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		provider, guard, e := readDirectory(ctx, tx, id)
		if e != nil {
			return e
		}
		m := out.Configuration.Metadata
		if provider.Revision != expected {
			return ErrDirectoryStale
		}
		floor, e := securitystate.Floor(ctx, tx, provider.SecurityGuardID, provider.SecurityGuardID)
		if e != nil {
			return e
		}
		if m.SecurityGuardID != provider.SecurityGuardID || out.Configuration.Spec.ForestGUID != provider.ForestGUID || uint64(m.SecurityGuardVersion) <= guard || uint64(m.SecurityGuardVersion) <= floor {
			return ErrDirectoryStale
		}
		for _, mapping := range out.Configuration.Spec.GroupMappings {
			var groupID string
			if e = securitystate.One(ctx, tx, `SELECT id FROM groups WHERE id=?`, []any{mapping.AccessGroupID}, func(r storage.IdentityRows) error { return r.Scan(&groupID) }); e != nil {
				return e
			}
		}
		raw, e := configmodel.CanonicalJSON(out.Configuration)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO directory_provider_versions(id,provider_id,guard_version,content_digest,canonical_json,author_id,author_fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?)`, m.VersionID, id, int64(m.SecurityGuardVersion), out.ContentDigest, string(raw), p.id, p.fingerprint, h.RecordedAt)
		if e != nil {
			return e
		}
		n, e := tx.Exec(ctx, `UPDATE directory_providers SET row_version=row_version+1 WHERE id=? AND row_version=?`, id, int64(expected))
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrDirectoryStale
		}
		return securitystate.Audit(ctx, tx, "identity.directory.version_proposed", p.id, map[string]any{"providerId": id, "versionId": m.VersionID, "contentDigest": out.ContentDigest})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
