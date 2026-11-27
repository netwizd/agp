package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/oidcclient"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type OIDCLoginMethod struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type OIDCLoginMethodList struct {
	Items []OIDCLoginMethod `json:"items"`
}
type OIDCAuthorizationView struct {
	AuthorizationURL string    `json:"authorizationUrl"`
	ExpiresAt        time.Time `json:"expiresAt"`
}
type OIDCCallbackResult struct {
	Transition Transition
	Terminal   bool
}
type oidcAuthorizationSecrets struct {
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

type oidcAuthorization struct {
	ID, StateHash, FlowID, BindingHash, CSRFHash, ProviderID, ProviderVersionID string
	ProviderGuardVersion                                                        securityjournal.UInt63
	Purpose, Audience, Origin, RedirectURI                                      string
	Epoch                                                                       securityjournal.UInt63
	Sealed                                                                      Sealed
	CreatedAt, ExpiresAt                                                        time.Time
	State, ResultFlowID                                                         string
}

func (s *OIDCService) LoginMethods(ctx context.Context, origin string) (out OIDCLoginMethodList, err error) {
	if origin != s.identity.Profile.LoginOrigin && origin != s.identity.Profile.ManagementOrigin {
		return out, ErrProof
	}
	out.Items = []OIDCLoginMethod{}
	err = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM oidc_providers WHERE enabled=TRUE ORDER BY id LIMIT 201`)
		if e != nil {
			return e
		}
		if len(ids) > 200 {
			return ErrDirectoryUnavailable
		}
		for _, id := range ids {
			p, e := currentOIDCProvider(ctx, tx, id)
			if errors.Is(e, ErrProof) {
				continue
			}
			if e != nil {
				return e
			}
			out.Items = append(out.Items, OIDCLoginMethod{p.ID, p.Name})
		}
		return nil
	})
	return
}
func oidcAuthorizationAAD(a oidcAuthorization) string {
	digest, _ := configmodel.Digest(struct {
		ID, Flow, Binding, Provider, Version, Purpose, Audience, Origin, Redirect string
		Epoch                                                                     securityjournal.UInt63
	}{a.ID, a.FlowID, a.BindingHash, a.ProviderID, a.ProviderVersionID, a.Purpose, a.Audience, a.Origin, a.RedirectURI, a.Epoch})
	return "AGP-OIDC-AUTHORIZATION-v1\n" + digest
}
func readOIDCAuthorization(ctx context.Context, tx storage.IdentityTx, state string) (*oidcAuthorization, error) {
	a := &oidcAuthorization{}
	e := securitystate.One(ctx, tx, `SELECT id,state_hash,flow_id,binding_hash,csrf_hash,provider_id,provider_version_id,provider_guard_version,purpose,audience,origin,redirect_uri,authority_epoch,key_id,nonce,ciphertext,created_at,expires_at,state,result_flow_id FROM oidc_authorizations WHERE state_hash=?`, []any{auth.TokenHash(state)}, func(r storage.IdentityRows) error {
		return r.Scan(&a.ID, &a.StateHash, &a.FlowID, &a.BindingHash, &a.CSRFHash, &a.ProviderID, &a.ProviderVersionID, &a.ProviderGuardVersion, &a.Purpose, &a.Audience, &a.Origin, &a.RedirectURI, &a.Epoch, &a.Sealed.KeyID, &a.Sealed.Nonce, &a.Sealed.Ciphertext, &a.CreatedAt, &a.ExpiresAt, &a.State, &a.ResultFlowID)
	})
	return a, e
}
func (s *OIDCService) BeginAuthorization(ctx context.Context, a FlowAuth, providerID, sourceIP string) (out OIDCAuthorizationView, err error) {
	if s.stateKeys == nil {
		return out, ErrDirectoryUnavailable
	}
	if a.CSRF == "" || !configmodel.ValidID(providerID) {
		return out, ErrProof
	}
	var d OIDCProviderDocument
	var head securityjournal.Head
	var pinned *flow
	err = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.identity.checked(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "pending_primary" || (f.Purpose != "login" && f.Purpose != "step_up") {
			return ErrProof
		}
		var count int
		e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM oidc_authorizations WHERE flow_id=?`, []any{f.ID}, func(r storage.IdentityRows) error { return r.Scan(&count) })
		if e != nil {
			return e
		}
		if count >= 3 {
			return ErrLimited
		}
		p, e := currentOIDCProvider(ctx, tx, providerID)
		if e != nil {
			return e
		}
		d = *p.Configuration
		head = h
		pinned = f
		return nil
	})
	if err != nil {
		return out, err
	}
	config, e := d.client(pinned.Audience)
	if e != nil {
		return out, e
	}
	provider, e := s.discover(ctx, d, pinned.Audience)
	if e != nil {
		return out, e
	}
	request, e := oidcclient.NewAuthorizationRequest(config.RegisteredRedirectURIs[0])
	if e != nil {
		return out, ErrDirectoryUnavailable
	}
	authorizationURL, e := provider.AuthorizationURL(request)
	if e != nil {
		return out, ErrDirectoryUnavailable
	}
	record := oidcAuthorization{ID: securitystate.ID("oidcauth"), StateHash: auth.TokenHash(request.State), FlowID: pinned.ID, BindingHash: pinned.BindingHash, CSRFHash: pinned.CSRFHash, ProviderID: providerID, ProviderVersionID: d.Metadata.VersionID, ProviderGuardVersion: d.Metadata.SecurityGuardVersion, Purpose: pinned.Purpose, Audience: pinned.Audience, Origin: pinned.Origin, RedirectURI: request.RedirectURI, Epoch: head.Epoch, CreatedAt: head.RecordedAt, ExpiresAt: pinned.ExpiresAt}
	plain, e := json.Marshal(oidcAuthorizationSecrets{request.Nonce, request.Verifier})
	if e != nil {
		return out, e
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	record.Sealed, e = s.stateKeys.ring.Seal(plain, oidcAuthorizationAAD(record))
	if e != nil {
		return out, ErrDirectoryUnavailable
	}
	var denial error
	err = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.identity.checked(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.ID != pinned.ID || f.State != "pending_primary" || f.BindingHash != pinned.BindingHash || f.Purpose != pinned.Purpose || f.Audience != pinned.Audience || f.Origin != pinned.Origin || h.Epoch != head.Epoch || h.RecordedAt.Before(head.RecordedAt) || h.RecordedAt.Sub(head.RecordedAt) > 10*time.Second {
			return ErrProof
		}
		p, e := currentOIDCProvider(ctx, tx, providerID)
		if e != nil {
			return e
		}
		if p.Configuration.Metadata != d.Metadata {
			return ErrProof
		}
		for _, bucket := range []string{"oidc_source_" + auth.TokenHash(sourceIP), "oidc_flow_" + f.ID} {
			if e = limit(ctx, tx, bucket, h.RecordedAt); e != nil {
				if errors.Is(e, ErrLimited) {
					denial = e
					return nil
				}
				return e
			}
		}
		var count int
		e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM oidc_authorizations WHERE flow_id=?`, []any{f.ID}, func(r storage.IdentityRows) error { return r.Scan(&count) })
		if e != nil {
			return e
		}
		if count >= 3 {
			return ErrLimited
		}
		if e = cancelOIDCPredecessors(ctx, tx, f.ID); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO oidc_authorizations(id,state_hash,flow_id,binding_hash,csrf_hash,provider_id,provider_version_id,provider_guard_version,purpose,audience,origin,redirect_uri,authority_epoch,key_id,nonce,ciphertext,created_at,expires_at,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')`, record.ID, record.StateHash, record.FlowID, record.BindingHash, record.CSRFHash, record.ProviderID, record.ProviderVersionID, int64(record.ProviderGuardVersion), record.Purpose, record.Audience, record.Origin, record.RedirectURI, int64(record.Epoch), record.Sealed.KeyID, record.Sealed.Nonce, record.Sealed.Ciphertext, record.CreatedAt, record.ExpiresAt)
		return e
	})
	if err != nil {
		return out, err
	}
	if denial != nil {
		return out, denial
	}
	return OIDCAuthorizationView{authorizationURL, record.ExpiresAt}, nil
}
func (s *OIDCService) failCallback(ctx context.Context, record *oidcAuthorization) error {
	return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		n, e := tx.Exec(ctx, `UPDATE oidc_authorizations SET state='failed',key_id='',nonce='',ciphertext='' WHERE id=? AND state='exchanging'`, record.ID)
		if e != nil {
			return e
		}
		if n == 0 {
			return nil
		}
		_, e = tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE id=? AND state='pending_primary'`, record.FlowID)
		return e
	})
}

func (s *OIDCService) Callback(ctx context.Context, a FlowAuth, providerID, state, code, providerError, providedIssuer string) (out OIDCCallbackResult, err error) {
	if s.stateKeys == nil {
		return out, ErrDirectoryUnavailable
	}
	if !configmodel.ValidID(providerID) || !oidcStateValue(state) || ((code == "") == (providerError == "")) || len(code) > 4096 || !oidcText(code, 4096) && code != "" || providerError != "" && !oidcText(providerError, 128) {
		return out, ErrProof
	}
	var record *oidcAuthorization
	var document OIDCProviderDocument
	var preNetwork securityjournal.Head
	var maximumAuthAge time.Duration
	var terminal bool
	err = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var e error
		record, e = readOIDCAuthorization(ctx, tx, state)
		if e != nil {
			return ErrProof
		}
		if record.ProviderID != providerID || record.Origin != a.Origin || (a.ID != "" && record.FlowID != a.ID) || !auth.ConstantTimeEqualHash(a.Binding, record.BindingHash) || record.Epoch != h.Epoch || !h.RecordedAt.Before(record.ExpiresAt) {
			return ErrProof
		}
		a.ID = record.FlowID
		pinned, e := readOIDCVersion(ctx, tx, record.ProviderID, record.ProviderVersionID)
		if e != nil {
			return ErrProof
		}
		if providedIssuer != "" && providedIssuer != pinned.Configuration.Spec.Issuer {
			return ErrProof
		}
		if record.State != "pending" {
			terminal = true
			return nil
		}
		f, e := s.identity.checked(ctx, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "pending_primary" || f.BindingHash != record.BindingHash || f.CSRFHash != record.CSRFHash || f.Purpose != record.Purpose || f.Audience != record.Audience || f.Origin != record.Origin {
			return ErrProof
		}
		p, e := currentOIDCProvider(ctx, tx, providerID)
		if e != nil {
			return e
		}
		if p.Configuration.Metadata.VersionID != record.ProviderVersionID || p.Configuration.Metadata.SecurityGuardVersion != record.ProviderGuardVersion {
			return ErrProof
		}
		document = *p.Configuration
		config, e := document.client(f.Audience)
		if e != nil || config.RegisteredRedirectURIs[0] != record.RedirectURI {
			return ErrProof
		}
		maximumAuthAge = config.MaximumAuthenticationAge
		n, e := tx.Exec(ctx, `UPDATE oidc_authorizations SET state='exchanging',exchange_started_at=? WHERE id=? AND state='pending'`, h.RecordedAt, record.ID)
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrProof
		}
		preNetwork = h
		return nil
	})
	if err != nil {
		return out, err
	}
	if terminal {
		return OIDCCallbackResult{Transition: Transition{View: FlowView{ID: record.FlowID}}, Terminal: true}, nil
	}
	if providerError != "" {
		if e := s.failCallback(ctx, record); e != nil {
			return out, e
		}
		return OIDCCallbackResult{Transition: Transition{View: FlowView{ID: record.FlowID}}, Terminal: true}, nil
	}
	// This record is already consumed. Every uncertain outcome requires a new
	// authorization; the code is never retried automatically or on callback replay.
	operation, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	failed := true
	defer func() {
		if failed {
			_ = s.failCallback(ctx, record)
		}
	}()
	plain, e := s.stateKeys.ring.Open(record.Sealed, oidcAuthorizationAAD(*record))
	if e != nil {
		return out, ErrDirectoryUnavailable
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	var secret oidcAuthorizationSecrets
	if configmodel.StrictJSON(bytes.NewReader(plain), &secret, 4096) != nil {
		return out, ErrProof
	}
	provider, e := s.discover(operation, document, record.Audience)
	if e != nil {
		return out, e
	}
	verified, e := provider.Exchange(operation, oidcclient.ExchangeRequest{Code: code, Nonce: secret.Nonce, Verifier: secret.Verifier, RedirectURI: record.RedirectURI})
	if e != nil {
		if errors.Is(e, oidcclient.ErrRejected) {
			return out, ErrProof
		}
		return out, ErrDirectoryUnavailable
	}
	claims, e := verified.Claims()
	if e != nil || claims.Issuer != document.Spec.Issuer || claims.AuthenticationTime.IsZero() {
		return out, ErrProof
	}
	var link *OIDCLinkView
	var directoryPin0 *directoryPin
	var securityVersion, passwordVersion uint64
	err = s.identity.Coordinator.Current(operation, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var id string
		e := securitystate.One(operation, tx, `SELECT id FROM oidc_links WHERE provider_id=? AND subject=?`, []any{providerID, claims.Subject}, func(r storage.IdentityRows) error { return r.Scan(&id) })
		if e != nil {
			return ErrProof
		}
		link, _, e = readOIDCLink(operation, tx, providerID, id)
		if e != nil {
			return e
		}
		if !link.Enabled || link.Configuration == nil {
			return ErrProof
		}
		floor, e := securitystate.Floor(operation, tx, link.SecurityGuardID, link.SecurityGuardID)
		if e != nil {
			return e
		}
		if uint64(link.Configuration.SecurityGuardVersion) < floor {
			return ErrProof
		}
		directoryPin0, e = directoryAuthPin(operation, tx, h, link.Configuration.PrincipalID)
		if e != nil {
			return e
		}
		if directoryPin0 == nil || directoryPin0.identity.ID != link.Configuration.DirectoryIdentityID {
			return ErrProof
		}
		e = securitystate.One(operation, tx, `SELECT security_version,password_version FROM users WHERE id=? AND blocked_at IS NULL`, []any{link.Configuration.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&securityVersion, &passwordVersion) })
		if e != nil {
			return ErrProof
		}
		return checkPrincipal(operation, tx, link.Configuration.PrincipalID, securityVersion, passwordVersion)
	})
	if err != nil {
		return out, err
	}
	if s.identity.directoryConnector == nil {
		return out, ErrDirectoryUnavailable
	}
	account, e := s.identity.directoryConnector.LiveCheck(operation, directoryPin0.document, directoryPin0.identity.ObjectGUID)
	if e != nil {
		return out, e
	}
	observation := &directoryObservation{pin: directoryPin0, account: account}
	binding, bindingHash, e := auth.NewToken()
	if e != nil {
		return out, e
	}
	newID := securitystate.ID("flow")
	amr, e := json.Marshal(claims.AMR)
	if e != nil {
		return out, e
	}
	err = s.identity.Coordinator.Current(operation, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, e := s.identity.checked(operation, tx, h, a)
		if e != nil {
			return e
		}
		if f.State != "pending_primary" || f.ID != record.FlowID || f.BindingHash != record.BindingHash || f.Purpose != record.Purpose || f.Audience != record.Audience || f.Origin != record.Origin || h.Epoch != preNetwork.Epoch || h.RecordedAt.Before(preNetwork.RecordedAt) || h.RecordedAt.Sub(preNetwork.RecordedAt) > 10*time.Second {
			return ErrProof
		}
		if !h.RecordedAt.Before(claims.ExpiresAt) || claims.IssuedAt.After(h.RecordedAt) || claims.AuthenticationTime.After(h.RecordedAt) || maximumAuthAge <= 0 || h.RecordedAt.Sub(claims.AuthenticationTime) > maximumAuthAge {
			return ErrProof
		}
		if f.Purpose == "step_up" {
			var sourcePrincipal, sourceHash, sourceAudience, sourceOrigin string
			e = securitystate.One(operation, tx, `SELECT user_id,token_hash,audience,audience_origin FROM sessions WHERE id=?`, []any{f.SourceSessionID}, func(r storage.IdentityRows) error {
				return r.Scan(&sourcePrincipal, &sourceHash, &sourceAudience, &sourceOrigin)
			})
			if e != nil || sourcePrincipal != link.Configuration.PrincipalID || sourceAudience != f.Audience || sourceOrigin != f.Origin {
				return ErrProof
			}
			if e = liveSession(operation, tx, f.SourceSessionID, sourcePrincipal, uint64(h.Epoch), h.RecordedAt); e != nil {
				return e
			}
			if e = securitystate.CheckManagementSessionFloors(operation, tx, sourceHash); e != nil {
				return e
			}
			if e = directoryCheckProjection(operation, tx, h, sourcePrincipal, "sessions", f.SourceSessionID); e != nil {
				return e
			}
		}
		p, e := currentOIDCProvider(operation, tx, providerID)
		if e != nil {
			return e
		}
		if p.Configuration.Metadata != document.Metadata {
			return ErrProof
		}
		current, _, e := readOIDCLink(operation, tx, providerID, link.ID)
		if e != nil {
			return e
		}
		if !current.Enabled || current.Configuration == nil || *current.Configuration != *link.Configuration {
			return ErrProof
		}
		floor, e := securitystate.Floor(operation, tx, current.SecurityGuardID, current.SecurityGuardID)
		if e != nil {
			return e
		}
		if uint64(current.Configuration.SecurityGuardVersion) < floor {
			return ErrProof
		}
		pin, e := directoryAuthPin(operation, tx, h, link.Configuration.PrincipalID)
		if e != nil {
			return e
		}
		if !directorySubjectProofMatches(pin, h, observation) {
			return ErrDirectoryUnavailable
		}
		if e = checkPrincipal(operation, tx, link.Configuration.PrincipalID, securityVersion, passwordVersion); e != nil {
			return e
		}
		var state0 string
		e = securitystate.One(operation, tx, `SELECT state FROM oidc_authorizations WHERE id=?`, []any{record.ID}, func(r storage.IdentityRows) error { return r.Scan(&state0) })
		if e != nil {
			return e
		}
		if state0 != "exchanging" {
			return ErrProof
		}
		if f.Audience == "management" {
			allowed, e := managementAdmissionTx(operation, tx, h, link.Configuration.PrincipalID)
			if e != nil {
				return e
			}
			if !allowed {
				return ErrProof
			}
		}
		var verifiedFactor, revokedFactor bool
		e = securitystate.One(operation, tx, `SELECT verified,revoked FROM mfa_factors WHERE principal_id=?`, []any{link.Configuration.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&verifiedFactor, &revokedFactor) })
		if e != nil && !errors.Is(e, storage.ErrNotFound) {
			return e
		}
		factorFloor, e := securitystate.Floor(operation, tx, link.Configuration.PrincipalID, FactorID(link.Configuration.PrincipalID))
		if e != nil {
			return e
		}
		next := "totp"
		if !verifiedFactor || revokedFactor {
			next = "totp_enrollment"
			if factorFloor > 0 {
				next = "recovery"
			}
		}
		n, e := tx.Exec(operation, `UPDATE identity_flows SET id=?,principal_id=?,security_version=?,password_version=?,binding_hash=?,oidc_authentication=FALSE,primary_verified=TRUE,primary_verified_at=?,state='pending_mfa',next_step=? WHERE id=? AND state='pending_primary'`, newID, link.Configuration.PrincipalID, int64(securityVersion), int64(passwordVersion), bindingHash, claims.AuthenticationTime, next, f.ID)
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrProof
		}
		if e = writeDirectoryContext(operation, tx, "identity_flows", newID, pin.context); e != nil {
			return e
		}
		c := &oidcContext{ProviderID: providerID, ProviderVersionID: document.Metadata.VersionID, ProviderGuardVersion: document.Metadata.SecurityGuardVersion, LinkID: link.ID, LinkVersionID: link.Configuration.ID, LinkGuardVersion: link.Configuration.SecurityGuardVersion, Issuer: claims.Issuer, Subject: claims.Subject, AuthTime: claims.AuthenticationTime, ACR: claims.ACR, AMRJSON: string(amr)}
		if e = writeOIDCContext(operation, tx, "identity_flows", newID, c); e != nil {
			return e
		}
		_, e = tx.Exec(operation, `UPDATE oidc_authorizations SET state='completed',result_flow_id=?,key_id='',nonce='',ciphertext='' WHERE id=? AND state='exchanging'`, newID, record.ID)
		if e != nil {
			return e
		}
		f.ID = newID
		f.State = "pending_mfa"
		f.NextStep = next
		out.Transition = Transition{View: f.view(), Binding: binding}
		return securitystate.Audit(operation, tx, "identity.oidc.primary_verified", link.Configuration.PrincipalID, map[string]any{"providerId": providerID, "linkId": link.ID, "audience": f.Audience})
	})
	if err != nil {
		return out, err
	}
	failed = false
	return out, nil
}
func oidcStateValue(s string) bool {
	if len(s) != 43 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
