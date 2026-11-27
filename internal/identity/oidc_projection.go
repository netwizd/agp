package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type oidcContext struct {
	ProviderID, ProviderVersionID string
	ProviderGuardVersion          securityjournal.UInt63
	LinkID, LinkVersionID         string
	LinkGuardVersion              securityjournal.UInt63
	Issuer, Subject               string
	AuthTime                      time.Time
	ACR, AMRJSON                  string
}

func oidcStoredContext(ctx context.Context, tx storage.IdentityTx, table, id string) (*oidcContext, error) {
	if table != "sessions" && table != "identity_flows" {
		return nil, ErrProof
	}
	var marker bool
	if e := securitystate.One(ctx, tx, `SELECT oidc_authentication FROM `+table+` WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&marker) }); e != nil {
		return nil, e
	}
	c := &oidcContext{}
	e := securitystate.One(ctx, tx, `SELECT provider_id,provider_version_id,provider_guard_version,link_id,link_version_id,link_guard_version,issuer,subject,auth_time,acr,amr_json FROM oidc_contexts WHERE entity_kind=? AND entity_id=?`, []any{table, id}, func(r storage.IdentityRows) error {
		return r.Scan(&c.ProviderID, &c.ProviderVersionID, &c.ProviderGuardVersion, &c.LinkID, &c.LinkVersionID, &c.LinkGuardVersion, &c.Issuer, &c.Subject, &c.AuthTime, &c.ACR, &c.AMRJSON)
	})
	if errors.Is(e, storage.ErrNotFound) {
		if marker {
			return nil, ErrProof
		}
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if !marker {
		return nil, ErrProof
	}
	return c, nil
}

// CheckOIDCProjection composes with the directory guard and performs no network
// I/O. Losing an OIDC context never turns that session into a direct AD login.
func CheckOIDCProjection(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal, table, id string) error {
	c, e := oidcStoredContext(ctx, tx, table, id)
	if e != nil {
		return e
	}
	if c == nil {
		return nil
	}
	p, e := currentOIDCProvider(ctx, tx, c.ProviderID)
	if e != nil {
		return e
	}
	if p.Issuer != c.Issuer || p.Configuration.Metadata.VersionID != c.ProviderVersionID || p.Configuration.Metadata.SecurityGuardVersion != c.ProviderGuardVersion {
		return ErrProof
	}
	link, g, e := readOIDCLink(ctx, tx, c.ProviderID, c.LinkID)
	if e != nil {
		return e
	}
	if !link.Enabled || link.Configuration == nil || link.Subject != c.Subject || link.Configuration.ID != c.LinkVersionID || link.Configuration.SecurityGuardVersion != c.LinkGuardVersion || link.Configuration.PrincipalID != principal {
		return ErrProof
	}
	floor, e := securitystate.Floor(ctx, tx, link.SecurityGuardID, link.SecurityGuardID)
	if e != nil {
		return e
	}
	if g < floor {
		return ErrProof
	}
	pin, e := directoryAuthPin(ctx, tx, h, principal)
	if e != nil {
		return e
	}
	if pin == nil || pin.identity.ID != link.Configuration.DirectoryIdentityID {
		return ErrProof
	}
	if h.RecordedAt.IsZero() || c.AuthTime.IsZero() || c.AuthTime.After(h.RecordedAt) {
		return ErrProof
	}
	var amr []string
	if json.Unmarshal([]byte(c.AMRJSON), &amr) != nil {
		return ErrProof
	}
	return nil
}
func CheckOIDCSessionProjection(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, hash string) error {
	var principal, id string
	e := securitystate.One(ctx, tx, `SELECT user_id,id FROM sessions WHERE token_hash=?`, []any{hash}, func(r storage.IdentityRows) error { return r.Scan(&principal, &id) })
	if e != nil {
		return e
	}
	return CheckOIDCProjection(ctx, tx, h, principal, "sessions", id)
}
func writeOIDCContext(ctx context.Context, tx storage.IdentityTx, table, id string, c *oidcContext) error {
	if table != "sessions" && table != "identity_flows" {
		return ErrProof
	}
	if c == nil {
		return nil
	}
	if _, e := tx.Exec(ctx, `INSERT INTO oidc_contexts(entity_kind,entity_id,provider_id,provider_version_id,provider_guard_version,link_id,link_version_id,link_guard_version,issuer,subject,auth_time,acr,amr_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, table, id, c.ProviderID, c.ProviderVersionID, int64(c.ProviderGuardVersion), c.LinkID, c.LinkVersionID, int64(c.LinkGuardVersion), c.Issuer, c.Subject, c.AuthTime, c.ACR, c.AMRJSON); e != nil {
		return e
	}
	n, e := tx.Exec(ctx, `UPDATE `+table+` SET oidc_authentication=TRUE WHERE id=? AND oidc_authentication=FALSE`, id)
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrProof
	}
	return nil
}
func CopyOIDCContext(ctx context.Context, tx storage.IdentityTx, sourceTable, sourceID, targetTable, targetID string) error {
	c, e := oidcStoredContext(ctx, tx, sourceTable, sourceID)
	if e != nil {
		return e
	}
	return writeOIDCContext(ctx, tx, targetTable, targetID, c)
}
