package identity

import (
	"context"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func readOIDCLink(ctx context.Context, tx storage.IdentityTx, provider, id string) (*OIDCLinkView, uint64, error) {
	if !configmodel.ValidID(provider) || !configmodel.ValidID(id) {
		return nil, 0, ErrOIDCInvalid
	}
	l := &OIDCLinkView{}
	var guard uint64
	var version string
	e := securitystate.One(ctx, tx, `SELECT id,provider_id,subject,guard_id,row_version,guard_version,enabled,COALESCE(active_version_id,'') FROM oidc_links WHERE id=? AND provider_id=?`, []any{id, provider}, func(r storage.IdentityRows) error {
		return r.Scan(&l.ID, &l.ProviderID, &l.Subject, &l.SecurityGuardID, &l.Revision, &guard, &l.Enabled, &version)
	})
	if e != nil {
		return nil, 0, e
	}
	if version != "" {
		v, e := readOIDCLinkVersion(ctx, tx, id, version)
		if e != nil {
			return nil, 0, e
		}
		if uint64(v.SecurityGuardVersion) != guard {
			return nil, 0, ErrOIDCStale
		}
		l.Configuration = v
	}
	return l, guard, nil
}
func readOIDCLinkVersion(ctx context.Context, tx storage.IdentityTx, id, version string) (*OIDCLinkVersion, error) {
	var raw, digest string
	e := securitystate.One(ctx, tx, `SELECT canonical_json,content_digest FROM oidc_link_versions WHERE link_id=? AND id=?`, []any{id, version}, func(r storage.IdentityRows) error { return r.Scan(&raw, &digest) })
	if e != nil {
		return nil, e
	}
	var v OIDCLinkVersion
	if configmodel.StrictJSON(strings.NewReader(raw), &v, 8192) != nil {
		return nil, ErrOIDCStale
	}
	actual := v.ContentDigest
	v.ContentDigest = ""
	d, e := configmodel.Digest(v)
	v.ContentDigest = actual
	if e != nil || actual != digest || d != digest || v.ID != version || v.LinkID != id {
		return nil, ErrOIDCStale
	}
	canonical, e := configmodel.CanonicalJSON(v)
	if e != nil || string(canonical) != raw {
		return nil, ErrOIDCStale
	}
	return &v, nil
}
func (s *OIDCService) GetLink(ctx context.Context, a DirectoryActor, provider, id string) (out *OIDCLinkView, err error) {
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		var e error
		out, _, e = readOIDCLink(ctx, tx, provider, id)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *OIDCService) ListLinks(ctx context.Context, a DirectoryActor, provider string, limit int, cursor string) (out OIDCLinkPage, err error) {
	if !configmodel.ValidID(provider) || limit < 1 || limit > 200 || (cursor != "" && !configmodel.ValidID(cursor)) {
		return out, ErrOIDCInvalid
	}
	out.Items = []OIDCLinkView{}
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		if _, _, e := readOIDCProvider(ctx, tx, provider); e != nil {
			return e
		}
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM oidc_links WHERE provider_id=? AND id>? ORDER BY id LIMIT ?`, provider, cursor, limit+1)
		if e != nil {
			return e
		}
		for i, id := range ids {
			if i == limit {
				out.NextCursor = out.Items[len(out.Items)-1].ID
				break
			}
			v, _, e := readOIDCLink(ctx, tx, provider, id)
			if e != nil {
				return e
			}
			out.Items = append(out.Items, *v)
		}
		return nil
	})
	return
}
func oidcTarget(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, identityID string, enabled bool) (*directoryPin, securityjournal.UInt63, error) {
	var principal string
	var sv securityjournal.UInt63
	e := securitystate.One(ctx, tx, `SELECT d.principal_id,u.security_version FROM directory_identities d JOIN users u ON u.id=d.principal_id WHERE d.id=?`, []any{identityID}, func(r storage.IdentityRows) error { return r.Scan(&principal, &sv) })
	if e != nil {
		return nil, 0, e
	}
	if enabled {
		p, e := directoryAuthPin(ctx, tx, h, principal)
		if e != nil {
			return nil, 0, e
		}
		if p == nil || p.identity.ID != identityID {
			return nil, 0, ErrProof
		}
		return p, sv, nil
	}
	// Revocation needs the previously linked identity's stable facts, never a live
	// positive AD read. A disabled/revoked target must remain revocable.
	link, e := readDirectoryIdentity(ctx, tx, principal)
	if e != nil {
		return nil, 0, e
	}
	if link == nil || link.ID != identityID {
		return nil, 0, ErrProof
	}
	provider, _, e := readDirectory(ctx, tx, link.ProviderID)
	if e != nil {
		return nil, 0, e
	}
	if provider.Configuration == nil {
		return nil, 0, ErrProof
	}
	v, e := directoryDocument(*provider.Configuration)
	if e != nil {
		return nil, 0, e
	}
	return &directoryPin{identity: *link, document: v.Configuration, digest: v.ContentDigest, epoch: h.Epoch, observedAt: h.RecordedAt, context: directoryContext{IdentityID: link.ID, IdentityVersion: link.AuthenticatorVersion, ProviderVersionID: v.Configuration.Metadata.VersionID, ProviderGuardVersion: v.Configuration.Metadata.SecurityGuardVersion}}, sv, nil
}

type oidcTargetProofKey struct{}

func (s *OIDCService) withLiveTarget(ctx context.Context, c OIDCLinkChange) (context.Context, error) {
	if !c.Enabled {
		return ctx, nil
	}
	if s.identity.directoryConnector == nil {
		return nil, ErrDirectoryUnavailable
	}
	var pin *directoryPin
	e := s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var e error
		pin, _, e = oidcTarget(ctx, tx, h, c.DirectoryIdentityID, true)
		return e
	})
	if e != nil {
		return nil, e
	}
	account, e := s.identity.directoryConnector.LiveCheck(ctx, pin.document, pin.identity.ObjectGUID)
	if e != nil {
		return nil, e
	}
	if account == nil || account.ObjectGUID != pin.identity.ObjectGUID || account.ForestGUID != pin.identity.ForestGUID {
		return nil, ErrProof
	}
	return context.WithValue(ctx, oidcTargetProofKey{}, &directoryObservation{pin: pin, account: account}), nil
}
func oidcTargetProof(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, c OIDCLinkChange) error {
	pin, sv, e := oidcTarget(ctx, tx, h, c.DirectoryIdentityID, c.Enabled)
	if e != nil {
		return e
	}
	if sv != c.ExpectedSecurityVersion || pin.identity.PrincipalID != c.TargetPrincipalID || pin.identity.AuthenticatorVersion != c.DirectoryAuthenticatorVersion || pin.context.ProviderVersionID != c.DirectoryProviderVersionID {
		return ErrOIDCStale
	}
	if c.Enabled {
		proof, _ := ctx.Value(oidcTargetProofKey{}).(*directoryObservation)
		if !directorySubjectProofMatches(pin, h, proof) {
			return ErrDirectoryUnavailable
		}
	}
	return nil
}
func (s *OIDCService) PlanLink(ctx context.Context, a DirectoryActor, provider, key string, in OIDCLinkCreate) (*OIDCSecurityOperation, error) {
	return s.planLink(ctx, a, provider, "", key, 0, in.Subject, OIDCLinkSuccessor{DirectoryIdentityID: in.DirectoryIdentityID, Enabled: true, ExpiresAt: in.ExpiresAt, Reason: in.Reason})
}
func (s *OIDCService) PlanLinkChange(ctx context.Context, a DirectoryActor, provider, id, key string, expected securityjournal.UInt63, in OIDCLinkSuccessor) (*OIDCSecurityOperation, error) {
	if expected == 0 {
		return nil, ErrOIDCInvalid
	}
	return s.planLink(ctx, a, provider, id, key, expected, "", in)
}
func (s *OIDCService) planLink(ctx context.Context, a DirectoryActor, provider, id, key string, expected securityjournal.UInt63, subject string, in OIDCLinkSuccessor) (out *OIDCSecurityOperation, err error) {
	if !configmodel.ValidID(provider) || !configmodel.ValidID(in.DirectoryIdentityID) || !directoryRequestKey.MatchString(key) || !directoryReason(in.Reason) || (id == "" && !oidcText(subject, 255)) {
		return nil, ErrOIDCInvalid
	}
	ctx, err = s.replayContext(ctx, a, "link_plan", key)
	if err != nil {
		return nil, err
	}
	if in.Enabled {
		var target *directoryPin
		err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, _ *directoryPrincipal) error {
			var e error
			target, _, e = oidcTarget(ctx, tx, h, in.DirectoryIdentityID, true)
			return e
		})
		if err != nil {
			return nil, err
		}
		if s.identity.directoryConnector == nil {
			return nil, ErrDirectoryUnavailable
		}
		account, e := s.identity.directoryConnector.LiveCheck(ctx, target.document, target.identity.ObjectGUID)
		if e != nil {
			return nil, e
		}
		if account == nil || account.ObjectGUID != target.identity.ObjectGUID || account.ForestGUID != target.identity.ForestGUID {
			return nil, ErrProof
		}
		ctx = context.WithValue(ctx, oidcTargetProofKey{}, &directoryObservation{pin: target, account: account})
	}
	fp, e := configmodel.Digest(struct {
		Provider, ID, Subject string
		Expected              securityjournal.UInt63
		Request               OIDCLinkSuccessor
	}{provider, id, subject, expected, in})
	if e != nil {
		return nil, e
	}
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, actor *directoryPrincipal) error {
		if id != "" {
			current, _, e := readOIDCLink(ctx, tx, provider, id)
			if e != nil {
				return e
			}
			if current.Revision != expected {
				return ErrOIDCStale
			}
		}
		if replay, e := oidcReplayRequest(ctx, tx, actor.id, "link_plan", key, fp); e != nil {
			return e
		} else if replay != "" {
			r, e := readOIDCOperation(ctx, tx, replay)
			if e != nil {
				return e
			}
			if r.operation.State != "applied" {
				if e = s.currentOperation(ctx, tx, h, r, false, false); e != nil {
					return e
				}
			}
			out = &r.operation
			return nil
		}
		if !in.ExpiresAt.After(h.RecordedAt) || in.ExpiresAt.After(h.RecordedAt.Add(5*time.Minute)) {
			return ErrOIDCInvalid
		}
		p, pg, e := readOIDCProvider(ctx, tx, provider)
		if e != nil {
			return e
		}
		if p.Configuration == nil {
			return ErrProof
		}
		if in.Enabled {
			if _, e = currentOIDCProvider(ctx, tx, provider); e != nil {
				return e
			}
		}
		var l *OIDCLinkView
		var old uint64
		if id == "" {
			l = &OIDCLinkView{ID: securitystate.ID("oidclink"), ProviderID: provider, Subject: subject, SecurityGuardID: securitystate.ID("guard_oidclink"), Revision: 1}
			_, e = tx.Exec(ctx, `INSERT INTO oidc_links(id,provider_id,subject,guard_id,row_version,guard_version,enabled,created_at) VALUES(?,?,?,?,1,0,FALSE,?)`, l.ID, provider, subject, l.SecurityGuardID, h.RecordedAt)
			if e != nil {
				return e
			}
		} else {
			l, old, e = readOIDCLink(ctx, tx, provider, id)
			if e != nil {
				return e
			}
			if l.Revision != expected {
				return ErrOIDCStale
			}
			if !in.Enabled && (l.Configuration == nil || l.Configuration.DirectoryIdentityID != in.DirectoryIdentityID) {
				return ErrOIDCInvalid
			}
		}
		floor, e := securitystate.Floor(ctx, tx, l.SecurityGuardID, l.SecurityGuardID)
		if e != nil {
			return e
		}
		var staged uint64
		if e = securitystate.One(ctx, tx, `SELECT COALESCE(MAX(guard_version),0) FROM oidc_link_versions WHERE link_id=?`, []any{l.ID}, func(r storage.IdentityRows) error { return r.Scan(&staged) }); e != nil {
			return e
		}
		next := max(old, floor, staged) + 1
		if next > uint64(securityjournal.MaxUInt63) || l.Revision >= securityjournal.MaxUInt63 {
			return ErrOIDCStale
		}
		target, sv, e := oidcTarget(ctx, tx, h, in.DirectoryIdentityID, in.Enabled)
		if e != nil {
			return e
		}
		v := OIDCLinkVersion{ID: securitystate.ID("oidclinkver"), LinkID: l.ID, SecurityGuardVersion: securityjournal.UInt63(next), DirectoryIdentityID: in.DirectoryIdentityID, PrincipalID: target.identity.PrincipalID}
		v.ContentDigest, e = configmodel.Digest(v)
		if e != nil {
			return e
		}
		raw, e := configmodel.CanonicalJSON(v)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO oidc_link_versions(id,link_id,guard_version,directory_identity_id,principal_id,content_digest,canonical_json) VALUES(?,?,?,?,?,?,?)`, v.ID, l.ID, int64(v.SecurityGuardVersion), v.DirectoryIdentityID, v.PrincipalID, v.ContentDigest, string(raw))
		if e != nil {
			return e
		}
		c := OIDCLinkChange{ProviderID: provider, ProviderVersionID: p.Configuration.Metadata.VersionID, ProviderGuardVersion: securityjournal.UInt63(pg), LinkID: l.ID, VersionID: v.ID, ContentDigest: v.ContentDigest, GuardID: l.SecurityGuardID, PreviousGuardVersion: securityjournal.UInt63(old), NextGuardVersion: v.SecurityGuardVersion, Subject: l.Subject, DirectoryIdentityID: v.DirectoryIdentityID, DirectoryProviderVersionID: target.context.ProviderVersionID, DirectoryAuthenticatorVersion: target.identity.AuthenticatorVersion, TargetPrincipalID: v.PrincipalID, ExpectedSecurityVersion: sv, ExpectedRowVersion: l.Revision, ExpectedAuthorityEpoch: h.Epoch, Enabled: in.Enabled, ExpiresAt: in.ExpiresAt.UTC().Truncate(time.Microsecond), Reason: in.Reason}
		if e = oidcTargetProof(ctx, tx, h, c); e != nil {
			return e
		}
		digest, e := configmodel.Digest(c)
		if e != nil {
			return e
		}
		out = &OIDCSecurityOperation{ID: securitystate.ID("oidcop"), Family: "oidc_identity_link", SubjectID: l.ID, CreatedBy: actor.id, CreatedAt: h.RecordedAt, RequestDigest: digest, State: "pending", ApprovalStatus: "pending", OIDCLinkChange: &c}
		return storeOIDCOperation(ctx, tx, h, actor, out, "link_plan", key, fp)
	})
	if err != nil {
		return nil, err
	}
	// Approval and execution repeat the bounded live target check. Planning a
	// disabled pending head is harmless; no link is enabled by this response.
	return out, nil
}
