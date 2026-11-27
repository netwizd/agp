package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/oidcclient"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// OIDCService is configured once before Coordinator.Recover. It only accepts
// verified transport results and preexisting stable AD identities.
type OIDCService struct {
	identity  *Service
	directory *DirectoryService
	connector *oidcclient.Connector
	stateKeys *OIDCStateKeyring
}

func NewOIDCService(identity *Service, connector *oidcclient.Connector) (*OIDCService, error) {
	if identity == nil || identity.Coordinator == nil || identity.directory == nil || identity.Keys == nil {
		return nil, ErrDirectoryUnavailable
	}
	s := &OIDCService{identity: identity, directory: identity.directory, connector: connector}
	identity.Coordinator.Register("oidc_security_change", s.materializeChange)
	return s, nil
}
func (s *OIDCService) actor(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a DirectoryActor, write, approve bool) (*directoryPrincipal, error) {
	p, e := s.directory.actor(ctx, tx, h, a, false, approve)
	if e != nil {
		return nil, e
	}
	if e = CheckOIDCSessionProjection(ctx, tx, h, a.TokenHash); e != nil {
		return nil, e
	}
	if write {
		if h.RecordedAt.Before(p.mfa) || h.RecordedAt.Sub(p.mfa) > 5*time.Minute {
			return nil, ErrOIDCReauthRequired
		}
		var primary time.Time
		e = securitystate.One(ctx, tx, `SELECT primary_at FROM sessions WHERE token_hash=? AND primary_at IS NOT NULL`, []any{a.TokenHash}, func(r storage.IdentityRows) error { return r.Scan(&primary) })
		if e != nil || h.RecordedAt.Before(primary) || h.RecordedAt.Sub(primary) > 5*time.Minute {
			return nil, ErrOIDCReauthRequired
		}
	}
	return p, nil
}
func (s *OIDCService) current(ctx context.Context, a DirectoryActor, write, approve bool, fn func(storage.IdentityTx, securityjournal.Head, *directoryPrincipal) error) error {
	if s == nil || s.identity == nil {
		return ErrDirectoryUnavailable
	}
	return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		p, e := s.actor(ctx, tx, h, a, write, approve)
		if e != nil {
			return e
		}
		return fn(tx, h, p)
	})
}

func (s *OIDCService) providerDocument(d OIDCProviderDocument) (*OIDCVersionView, error) {
	v, e := oidcDocument(d)
	if e != nil {
		return nil, e
	}
	for _, c := range v.Configuration.Spec.Clients {
		o := s.identity.Profile.LoginOrigin
		if c.Purpose == "management" {
			o = s.identity.Profile.ManagementOrigin
		}
		if c.RedirectURI != o+"/auth/v2/oidc/providers/"+d.Metadata.ID+"/callback" {
			return nil, ErrOIDCInvalid
		}
	}
	return v, nil
}
func readOIDCVersion(ctx context.Context, tx storage.IdentityTx, id, version string) (*OIDCVersionView, error) {
	if !configmodel.ValidID(id) || !configmodel.ValidID(version) {
		return nil, ErrOIDCInvalid
	}
	var raw, digest string
	e := securitystate.One(ctx, tx, `SELECT canonical_json,content_digest FROM oidc_provider_versions WHERE provider_id=? AND id=?`, []any{id, version}, func(r storage.IdentityRows) error { return r.Scan(&raw, &digest) })
	if e != nil {
		return nil, e
	}
	d, e := ParseOIDCProvider(strings.NewReader(raw))
	if e != nil {
		return nil, ErrOIDCStale
	}
	v, e := oidcDocument(*d)
	if e != nil || v.ContentDigest != digest || d.Metadata.ID != id || d.Metadata.VersionID != version {
		return nil, ErrOIDCStale
	}
	canonical, e := configmodel.CanonicalJSON(d)
	if e != nil || string(canonical) != raw {
		return nil, ErrOIDCStale
	}
	return v, nil
}
func readOIDCProvider(ctx context.Context, tx storage.IdentityTx, id string) (*OIDCProviderView, uint64, error) {
	if !configmodel.ValidID(id) {
		return nil, 0, ErrOIDCInvalid
	}
	p := &OIDCProviderView{}
	var guard uint64
	var version string
	e := securitystate.One(ctx, tx, `SELECT id,name,issuer,guard_id,row_version,guard_version,enabled,COALESCE(active_version_id,'') FROM oidc_providers WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&p.ID, &p.Name, &p.Issuer, &p.SecurityGuardID, &p.Revision, &guard, &p.Enabled, &version)
	})
	if e != nil {
		return nil, 0, e
	}
	if version != "" {
		v, e := readOIDCVersion(ctx, tx, id, version)
		if e != nil {
			return nil, 0, e
		}
		if v.Configuration.Metadata.SecurityGuardID != p.SecurityGuardID || uint64(v.Configuration.Metadata.SecurityGuardVersion) != guard || v.Configuration.Spec.Issuer != p.Issuer {
			return nil, 0, ErrOIDCStale
		}
		p.Configuration = &v.Configuration
	}
	return p, guard, nil
}
func currentOIDCProvider(ctx context.Context, tx storage.IdentityTx, id string) (*OIDCProviderView, error) {
	p, g, e := readOIDCProvider(ctx, tx, id)
	if e != nil {
		return nil, e
	}
	if !p.Enabled || p.Configuration == nil {
		return nil, ErrProof
	}
	f, e := securitystate.Floor(ctx, tx, p.SecurityGuardID, p.SecurityGuardID)
	if e != nil {
		return nil, e
	}
	if g < f {
		return nil, ErrProof
	}
	return p, nil
}
func (s *OIDCService) CreateProvider(ctx context.Context, a DirectoryActor, in OIDCProviderCreate) (out *OIDCProviderView, err error) {
	if !oidcText(in.Name, 512) || utf8.RuneCountInString(in.Name) > 128 || strings.TrimSpace(in.Name) == "" || !oidcHTTPS(in.Issuer) {
		return nil, ErrOIDCInvalid
	}
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		out = &OIDCProviderView{ID: securitystate.ID("oidc"), Name: in.Name, Issuer: in.Issuer, SecurityGuardID: securitystate.ID("guard_oidc"), Revision: 1}
		_, e := tx.Exec(ctx, `INSERT INTO oidc_providers(id,name,issuer,guard_id,row_version,guard_version,enabled,created_at) VALUES(?,?,?,?,1,0,FALSE,?)`, out.ID, out.Name, out.Issuer, out.SecurityGuardID, h.RecordedAt)
		if e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "identity.oidc.provider_created", p.id, map[string]any{"providerId": out.ID})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *OIDCService) GetProvider(ctx context.Context, a DirectoryActor, id string) (out *OIDCProviderView, err error) {
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		var e error
		out, _, e = readOIDCProvider(ctx, tx, id)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *OIDCService) ListProviders(ctx context.Context, a DirectoryActor, limit int, cursor string) (out OIDCProviderPage, err error) {
	if limit < 1 || limit > 200 || (cursor != "" && !configmodel.ValidID(cursor)) {
		return out, ErrOIDCInvalid
	}
	out.Items = []OIDCProviderView{}
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM oidc_providers WHERE id>? ORDER BY id LIMIT ?`, cursor, limit+1)
		if e != nil {
			return e
		}
		used := 256
		for _, id := range ids {
			v, _, e := readOIDCProvider(ctx, tx, id)
			if e != nil {
				return e
			}
			raw, _ := json.Marshal(v)
			if len(out.Items) == limit || used+len(raw) > 1536<<10 {
				out.NextCursor = out.Items[len(out.Items)-1].ID
				break
			}
			used += len(raw)
			out.Items = append(out.Items, *v)
		}
		return nil
	})
	return
}
func (s *OIDCService) GetVersion(ctx context.Context, a DirectoryActor, id, version string) (out *OIDCVersionView, err error) {
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		var e error
		out, e = readOIDCVersion(ctx, tx, id, version)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *OIDCService) ProposeVersion(ctx context.Context, a DirectoryActor, id string, expected securityjournal.UInt63, in OIDCProviderDocument) (out *OIDCVersionView, err error) {
	out, err = s.providerDocument(in)
	if err != nil {
		return nil, err
	}
	if id != in.Metadata.ID || expected == 0 || expected >= securityjournal.MaxUInt63 {
		return nil, ErrOIDCInvalid
	}
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, actor *directoryPrincipal) error {
		p, g, e := readOIDCProvider(ctx, tx, id)
		if e != nil {
			return e
		}
		f, e := securitystate.Floor(ctx, tx, p.SecurityGuardID, p.SecurityGuardID)
		if e != nil {
			return e
		}
		m := out.Configuration.Metadata
		if p.Revision != expected || p.SecurityGuardID != m.SecurityGuardID || p.Issuer != out.Configuration.Spec.Issuer || uint64(m.SecurityGuardVersion) <= g || uint64(m.SecurityGuardVersion) <= f {
			return ErrOIDCStale
		}
		raw, e := configmodel.CanonicalJSON(out.Configuration)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO oidc_provider_versions(id,provider_id,guard_version,content_digest,canonical_json,author_id,author_fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?)`, m.VersionID, id, int64(m.SecurityGuardVersion), out.ContentDigest, string(raw), actor.id, actor.fingerprint, h.RecordedAt)
		if e != nil {
			return e
		}
		n, e := tx.Exec(ctx, `UPDATE oidc_providers SET row_version=row_version+1 WHERE id=? AND row_version=?`, id, int64(expected))
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrOIDCStale
		}
		return securitystate.Audit(ctx, tx, "identity.oidc.version_proposed", actor.id, map[string]any{"providerId": id, "versionId": m.VersionID, "contentDigest": out.ContentDigest})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type oidcConnectivity struct {
	digest     string
	epoch      securityjournal.UInt63
	observedAt time.Time
}
type oidcConnectivityKey struct{}

func (s *OIDCService) discover(ctx context.Context, d OIDCProviderDocument, purpose string) (*oidcclient.Provider, error) {
	if s.connector == nil {
		return nil, ErrDirectoryUnavailable
	}
	c, e := d.client(purpose)
	if e != nil {
		return nil, e
	}
	p, e := s.connector.Discover(ctx, c)
	if e != nil {
		return nil, ErrDirectoryUnavailable
	}
	return p, nil
}
func (s *OIDCService) connectivity(ctx context.Context, v *OIDCVersionView, h securityjournal.Head) (context.Context, error) {
	var providers []*oidcclient.Provider
	for _, purpose := range []string{"login", "management"} {
		p, e := s.discover(ctx, v.Configuration, purpose)
		if e != nil {
			return nil, e
		}
		providers = append(providers, p)
	}
	if !providers[0].DistinctClientBinding(providers[1]) {
		return nil, ErrDirectoryUnavailable
	}
	return context.WithValue(ctx, oidcConnectivityKey{}, oidcConnectivity{v.ContentDigest, h.Epoch, h.RecordedAt}), nil
}
func (s *OIDCService) TestProvider(ctx context.Context, a DirectoryActor, id, version string) (out *OIDCProviderTest, err error) {
	var v *OIDCVersionView
	var head securityjournal.Head
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, _ *directoryPrincipal) error {
		var e error
		v, e = readOIDCVersion(ctx, tx, id, version)
		head = h
		return e
	})
	if err != nil {
		return nil, err
	}
	_, testErr := s.connectivity(ctx, v, head)
	out = &OIDCProviderTest{OperationID: securitystate.ID("oidctest"), ProviderID: id, VersionID: version, State: "failed", ReasonCode: "identity_provider_unavailable"}
	if testErr == nil {
		out.State = "passed"
		out.ReasonCode = "verified"
	}
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		if h.Epoch != head.Epoch || h.RecordedAt.Before(head.RecordedAt) || h.RecordedAt.Sub(head.RecordedAt) > 10*time.Second {
			return ErrDirectoryUnavailable
		}
		current, e := readOIDCVersion(ctx, tx, id, version)
		if e != nil {
			return e
		}
		if current.ContentDigest != v.ContentDigest {
			return ErrOIDCStale
		}
		_, e = tx.Exec(ctx, `INSERT INTO oidc_provider_tests(id,provider_id,version_id,content_digest,authority_epoch,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`, out.OperationID, id, version, v.ContentDigest, int64(h.Epoch), out.State, h.RecordedAt, h.RecordedAt.Add(5*time.Minute))
		if e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "identity.oidc.provider_tested", p.id, map[string]any{"providerId": id, "versionId": version, "state": out.State})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *OIDCService) GetTest(ctx context.Context, a DirectoryActor, id, test string) (out *OIDCProviderTest, err error) {
	out = &OIDCProviderTest{}
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		e := securitystate.One(ctx, tx, `SELECT id,provider_id,version_id,state FROM oidc_provider_tests WHERE id=? AND provider_id=?`, []any{test, id}, func(r storage.IdentityRows) error {
			return r.Scan(&out.OperationID, &out.ProviderID, &out.VersionID, &out.State)
		})
		out.ReasonCode = "identity_provider_unavailable"
		if out.State == "passed" {
			out.ReasonCode = "verified"
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func oidcTestCurrent(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, v *OIDCVersionView) error {
	var id string
	e := securitystate.One(ctx, tx, `SELECT id FROM oidc_provider_tests WHERE provider_id=? AND version_id=? AND content_digest=? AND authority_epoch=? AND state='passed' AND created_at<=? AND expires_at>? ORDER BY created_at DESC LIMIT 1`, []any{v.Configuration.Metadata.ID, v.Configuration.Metadata.VersionID, v.ContentDigest, int64(h.Epoch), h.RecordedAt, h.RecordedAt}, func(r storage.IdentityRows) error { return r.Scan(&id) })
	if errors.Is(e, storage.ErrNotFound) {
		return ErrDirectoryUnavailable
	}
	return e
}
