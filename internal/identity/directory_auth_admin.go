package identity

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// CheckDirectorySessionProjection is the final transaction-side guard after a
// request's Session performed the live AD read. It closes a provider/link change
// between HTTP authentication and a management mutation without network in TX.
func CheckDirectorySessionProjection(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, tokenHash string) error {
	if e := securitystate.CheckManagementSessionFloors(ctx, tx, tokenHash); e != nil {
		return e
	}
	var principal, id string
	e := securitystate.One(ctx, tx, `SELECT user_id,id FROM sessions WHERE token_hash=?`, []any{tokenHash}, func(r storage.IdentityRows) error { return r.Scan(&principal, &id) })
	if e != nil {
		return e
	}
	if e = directoryCheckProjection(ctx, tx, h, principal, "sessions", id); e != nil {
		return e
	}
	pin, e := directoryAuthPin(ctx, tx, h, principal)
	if e != nil {
		return e
	}
	if pin == nil {
		return nil
	}
	proof, ok := ctx.Value(directoryRequestProofKey{}).(*directoryRequestProof)
	if !ok || proof == nil || proof.hash != tokenHash || proof.sessionID != id || proof.principalID != principal || proof.observation == nil {
		return ErrDirectoryUnavailable
	}
	return proof.observation.check(ctx, tx, h, principal, "sessions", id)
}

type DirectoryAccessView struct {
	PrincipalID    string                 `json:"principalId"`
	Manage         bool                   `json:"manage"`
	Approve        bool                   `json:"approve"`
	AuthorityEpoch securityjournal.UInt63 `json:"authorityEpoch"`
}

func (s *DirectoryService) Access(ctx context.Context, a DirectoryActor) (out *DirectoryAccessView, err error) {
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		out = &DirectoryAccessView{PrincipalID: p.id, Manage: true, AuthorityEpoch: h.Epoch}
		_, e := directorySubject(ctx, tx, p.id, h, true)
		if errors.Is(e, storage.ErrPermissionDenied) {
			return nil
		}
		if e != nil {
			return e
		}
		out.Approve = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type DirectoryIdentityPage struct {
	Items      []DirectoryIdentityView `json:"items"`
	NextCursor string                  `json:"nextCursor,omitempty"`
}

func (s *DirectoryService) ListIdentities(ctx context.Context, a DirectoryActor, provider string, limit int, cursor string) (out DirectoryIdentityPage, err error) {
	if !configmodel.ValidID(provider) || limit < 1 || limit > 200 || (cursor != "" && !configmodel.ValidID(cursor)) {
		return out, ErrDirectoryInvalid
	}
	out.Items = []DirectoryIdentityView{}
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		if _, _, e := readDirectory(ctx, tx, provider); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,revoked FROM directory_identities WHERE provider_id=? AND id>? ORDER BY id LIMIT ?`, provider, cursor, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v DirectoryIdentityView
			if e = rows.Scan(&v.ID, &v.PrincipalID, &v.ProviderID, &v.ForestGUID, &v.ObjectGUID, &v.AuthenticatorVersion, &v.Revoked); e != nil {
				return e
			}
			out.Items = append(out.Items, v)
		}
		if e = rows.Err(); e != nil {
			return e
		}
		if len(out.Items) > limit {
			out.NextCursor = out.Items[limit-1].ID
			out.Items = out.Items[:limit]
		}
		return nil
	})
	if err != nil {
		return DirectoryIdentityPage{}, err
	}
	return out, nil
}

type directoryRevokeIntent struct {
	IdentityID, PrincipalID, ActorID, Reason string
	PreviousVersion, NextVersion             securityjournal.UInt63
}

func (s *DirectoryService) RevokeIdentity(ctx context.Context, a DirectoryActor, provider, identityID, reason string) error {
	if !configmodel.ValidID(provider) || !configmodel.ValidID(identityID) || !directoryReason(reason) {
		return ErrDirectoryInvalid
	}
	return s.coordinator.ExecuteDynamic(ctx, "directory_identity_revoke", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		p, e := s.actor(ctx, tx, h, a, true, false)
		if e != nil {
			return nil, nil, e
		}
		var principal string
		var version securityjournal.UInt63
		var revoked bool
		e = securitystate.One(ctx, tx, `SELECT principal_id,authenticator_version,revoked FROM directory_identities WHERE id=? AND provider_id=?`, []any{identityID, provider}, func(r storage.IdentityRows) error { return r.Scan(&principal, &version, &revoked) })
		if e != nil {
			return nil, nil, e
		}
		if revoked {
			return nil, nil, ErrDirectoryStale
		}
		floor, e := securitystate.Floor(ctx, tx, principal, identityID)
		if e != nil {
			return nil, nil, e
		}
		next := max(uint64(version), floor) + 1
		if next > uint64(securityjournal.MaxUInt63) {
			return nil, nil, ErrDirectoryStale
		}
		in := directoryRevokeIntent{IdentityID: identityID, PrincipalID: principal, ActorID: p.id, Reason: reason, PreviousVersion: version, NextVersion: securityjournal.UInt63(next)}
		raw, e := configmodel.CanonicalJSON(in)
		if e != nil {
			return nil, nil, e
		}
		return raw, []securityjournal.AppendRequest{securitystate.FloorRequest(p.id, principal, identityID, next)}, nil
	})
}
func materializeDirectoryIdentityRevoke(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in directoryRevokeIntent
	if json.Unmarshal(raw, &in) != nil || in.NextVersion <= in.PreviousVersion {
		return ErrDirectoryStale
	}
	floor, e := securitystate.Floor(ctx, tx, in.PrincipalID, in.IdentityID)
	if e != nil {
		return e
	}
	if floor < uint64(in.NextVersion) {
		return ErrDirectoryStale
	}
	n, e := tx.Exec(ctx, `UPDATE directory_identities SET revoked=TRUE WHERE id=? AND principal_id=? AND authenticator_version=?`, in.IdentityID, in.PrincipalID, int64(in.PreviousVersion))
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrDirectoryStale
	}
	return securitystate.Audit(ctx, tx, "identity.directory.identity_revoked", in.ActorID, map[string]any{"identityId": in.IdentityID, "principalId": in.PrincipalID, "reason": in.Reason})
}

// The key and payload are private: neither serialized API data nor a caller
// boolean can mint a proof. It remains bound to one session/token and short
// independent-time window, and all provider/link pins are rechecked in TX.
type directoryRequestProofKey struct{}
type directoryRequestProof struct {
	hash, sessionID, principalID string
	observation                  *directoryObservation
}

func (s *Service) WithCurrentSession(ctx context.Context, hash, audience, origin string, fn func(context.Context, *domain.SessionContext) error) error {
	if fn == nil {
		return ErrProof
	}
	session, observation, e := s.sessionWithDirectoryProof(ctx, hash, audience, origin)
	if e != nil {
		return e
	}
	if observation != nil {
		ctx = context.WithValue(ctx, directoryRequestProofKey{}, &directoryRequestProof{hash: hash, sessionID: session.ID, principalID: session.User.ID, observation: observation})
	}
	return fn(ctx, session)
}
