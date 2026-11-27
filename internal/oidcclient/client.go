package oidcclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/netwizd/agp/internal/configmodel"
	"golang.org/x/oauth2"
)

// Config is copied into an immutable provider. Management and login use
// separate clients/configurations; the identity layer enforces that separation.
type Config struct {
	Issuer, ClientID, ClientSecretVersionID, CASecretVersionID string
	EndpointPins                                               EndpointPins
	Purpose                                                    string // login or management
	RegisteredRedirectURIs                                     []string
	// Optional max_age requests force auth_time. Without it, a present auth_time
	// is still bounded to 24h. ID tokens must be issued in the last five minutes.
	MaximumAuthenticationAge time.Duration
}

// EndpointPins freezes the three security-sensitive discovery endpoints. A
// nonzero value must contain all three; identity providers always supply it.
type EndpointPins struct{ AuthorizationEndpoint, TokenEndpoint, JWKSURI string }
type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ResponseTypes         []string `json:"response_types_supported"`
	GrantTypes            []string `json:"grant_types_supported"`
	Algorithms            []string `json:"id_token_signing_alg_values_supported"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	PKCEMethods           []string `json:"code_challenge_methods_supported"`
}
type Provider struct {
	c                  *Connector
	config             Config
	metadata           discovery
	secretHash, caHash [32]byte
}

// DistinctClientBinding confirms purpose separation using verified secret
// contents without exposing either the secrets or their digests to consumers.
func (p *Provider) DistinctClientBinding(other *Provider) bool {
	return p != nil && other != nil && p.c != nil && p.c == other.c &&
		p.config.Issuer == other.config.Issuer && p.config.Purpose != other.config.Purpose &&
		p.config.ClientID != other.config.ClientID && p.secretHash != other.secretHash && p.caHash == other.caHash &&
		p.metadata.AuthorizationEndpoint == other.metadata.AuthorizationEndpoint &&
		p.metadata.TokenEndpoint == other.metadata.TokenEndpoint && p.metadata.JWKSURI == other.metadata.JWKSURI
}

type AuthorizationRequest struct{ State, Nonce, Verifier, RedirectURI string }
type ExchangeRequest struct{ Code, Nonce, Verifier, RedirectURI string }
type Claims struct {
	Issuer, Subject                         string
	ExpiresAt, IssuedAt, AuthenticationTime time.Time
	ACR                                     string
	AMR                                     []string
}

// VerifiedIdentity has no exported fields or public constructor. A zero value
// cannot manufacture evidence; Claims returns a detached copy only after verify.
type VerifiedIdentity struct {
	claims   Claims
	verified bool
}

func (v *VerifiedIdentity) Claims() (Claims, error) {
	if v == nil || !v.verified {
		return Claims{}, ErrRejected
	}
	out := v.claims
	out.AMR = append([]string{}, out.AMR...)
	return out, nil
}

func normalizeConfig(c *Connector, in Config) (Config, error) {
	if c == nil || !c.allowedURL(in.Issuer) || !text(in.ClientID, 256) || !configmodel.ValidID(in.ClientSecretVersionID) || !configmodel.ValidID(in.CASecretVersionID) || in.ClientSecretVersionID == in.CASecretVersionID || (in.Purpose != "login" && in.Purpose != "management") || len(in.RegisteredRedirectURIs) < 1 || len(in.RegisteredRedirectURIs) > 8 {
		return Config{}, ErrInvalid
	}
	if in.MaximumAuthenticationAge < 0 || in.MaximumAuthenticationAge > 24*time.Hour || in.MaximumAuthenticationAge%time.Second != 0 {
		return Config{}, ErrInvalid
	}
	if in.EndpointPins != (EndpointPins{}) && (!c.allowedURL(in.EndpointPins.AuthorizationEndpoint) || !c.allowedURL(in.EndpointPins.TokenEndpoint) || !c.allowedURL(in.EndpointPins.JWKSURI)) {
		return Config{}, ErrInvalid
	}
	in.RegisteredRedirectURIs = append([]string{}, in.RegisteredRedirectURIs...)
	seen := map[string]bool{}
	for _, redirect := range in.RegisteredRedirectURIs {
		if _, e := httpsURL(redirect); e != nil || seen[redirect] {
			return Config{}, ErrInvalid
		}
		seen[redirect] = true
	}
	return in, nil
}
func (c *Connector) Discover(ctx context.Context, input Config) (*Provider, error) {
	config, e := normalizeConfig(c, input)
	if e != nil {
		return nil, e
	}
	op, e := c.operation(ctx, config)
	if e != nil {
		return nil, e
	}
	defer op.close()
	raw, e := op.get(strings.TrimSuffix(config.Issuer, "/")+"/.well-known/openid-configuration", 64<<10)
	if e != nil {
		return nil, e
	}
	var metadata discovery
	if safeJSON(raw, &metadata) != nil || metadata.Issuer != config.Issuer || !c.allowedURL(metadata.AuthorizationEndpoint) || !c.allowedURL(metadata.TokenEndpoint) || !c.allowedURL(metadata.JWKSURI) || !slices.Contains(metadata.ResponseTypes, "code") || !slices.Contains(metadata.Algorithms, "RS256") || !slices.Contains(metadata.TokenAuthMethods, "client_secret_basic") || !slices.Contains(metadata.PKCEMethods, "S256") || (len(metadata.GrantTypes) > 0 && !slices.Contains(metadata.GrantTypes, "authorization_code")) {
		return nil, ErrUnavailable
	}
	if pins := config.EndpointPins; pins != (EndpointPins{}) && pins != (EndpointPins{metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.JWKSURI}) {
		return nil, ErrUnavailable
	}
	// Check the live JWKS endpoint under the same bounded/pinned operation.
	// Keys are deliberately not retained as positive authentication evidence.
	jwks, e := op.get(metadata.JWKSURI, 128<<10)
	if e != nil {
		return nil, e
	}
	if _, e = parseKeySet(jwks); e != nil {
		return nil, ErrUnavailable
	}
	// Discovery proves current CA/host and endpoint policy, not user authentication.
	if op.ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return &Provider{c: c, config: config, metadata: metadata, secretHash: secretDigest(op.secrets), caHash: sha256.Sum256(op.secrets.CACertificatesPEM)}, nil
}
func (op *operation) get(endpoint string, limit int) ([]byte, error) {
	request, e := http.NewRequestWithContext(op.ctx, http.MethodGet, endpoint, nil)
	if e != nil {
		return nil, ErrUnavailable
	}
	response, e := op.client.Do(request)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !jsonMediaType(response.Header.Get("Content-Type")) {
		return nil, ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, int64(limit+1)))
	if e != nil || len(raw) > limit {
		return nil, ErrUnavailable
	}
	return raw, nil
}

var pkce = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
var randomValue = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)

func NewAuthorizationRequest(redirect string) (AuthorizationRequest, error) {
	values := make([]string, 3)
	for i := range values {
		var b [32]byte
		if _, e := rand.Read(b[:]); e != nil {
			return AuthorizationRequest{}, ErrUnavailable
		}
		values[i] = base64.RawURLEncoding.EncodeToString(b[:])
	}
	return AuthorizationRequest{State: values[0], Nonce: values[1], Verifier: values[2], RedirectURI: redirect}, nil
}
func (p *Provider) validRedirect(redirect string) bool {
	return p != nil && p.c != nil && slices.Contains(p.config.RegisteredRedirectURIs, redirect)
}
func (p *Provider) oauth(secret string, redirect string) *oauth2.Config {
	return &oauth2.Config{ClientID: p.config.ClientID, ClientSecret: secret, Endpoint: oauth2.Endpoint{AuthURL: p.metadata.AuthorizationEndpoint, TokenURL: p.metadata.TokenEndpoint, AuthStyle: oauth2.AuthStyleInHeader}, RedirectURL: redirect, Scopes: []string{"openid"}}
}
func (p *Provider) AuthorizationURL(in AuthorizationRequest) (string, error) {
	if !p.validRedirect(in.RedirectURI) || !randomValue.MatchString(in.State) || !randomValue.MatchString(in.Nonce) || !pkce.MatchString(in.Verifier) {
		return "", ErrInvalid
	}
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(in.Verifier), oidc.Nonce(in.Nonce)}
	if p.config.MaximumAuthenticationAge > 0 {
		options = append(options, oauth2.SetAuthURLParam("max_age", strconv.FormatInt(int64(p.config.MaximumAuthenticationAge/time.Second), 10)))
	}
	return p.oauth("", in.RedirectURI).AuthCodeURL(in.State, options...), nil
}
func (p *Provider) Exchange(ctx context.Context, in ExchangeRequest) (*VerifiedIdentity, error) {
	if !p.validRedirect(in.RedirectURI) || !randomValue.MatchString(in.Nonce) || !pkce.MatchString(in.Verifier) || !text(in.Code, 4096) {
		return nil, ErrInvalid
	}
	op, e := p.c.operation(ctx, p.config)
	if e != nil {
		return nil, e
	}
	defer op.close()
	if secretDigest(op.secrets) != p.secretHash || sha256.Sum256(op.secrets.CACertificatesPEM) != p.caHash {
		return nil, ErrUnavailable
	}
	// One explicit Basic-auth code exchange. No AuthStyle autodetection, refresh
	// source, HTTP redirects, keep-alive reuse or background JWKS fetch/retry.
	token, e := p.oauth(string(op.secrets.ClientSecret), in.RedirectURI).Exchange(context.WithValue(op.ctx, oauth2.HTTPClient, op.client), in.Code, oauth2.VerifierOption(in.Verifier))
	if e != nil {
		var rejected *oauth2.RetrieveError
		if errors.As(e, &rejected) && rejected.Response != nil && rejected.Response.StatusCode >= 400 && rejected.Response.StatusCode < 500 {
			return nil, ErrRejected
		}
		return nil, ErrUnavailable
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 64<<10 || len(raw) < 16 {
		return nil, ErrRejected
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(parts[0]) > 4096 || len(parts[1]) > 64<<10 {
		return nil, ErrRejected
	}
	headerBytes, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return nil, ErrRejected
	}
	var header struct {
		Algorithm string   `json:"alg"`
		KeyID     string   `json:"kid"`
		Critical  []string `json:"crit"`
	}
	if safeJSON(headerBytes, &header) != nil || header.Algorithm != "RS256" || !text(header.KeyID, 128) || len(header.Critical) != 0 {
		return nil, ErrRejected
	}
	payload, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || len(payload) > 48<<10 {
		return nil, ErrRejected
	}
	var claims tokenClaims
	if safeJSON(payload, &claims) != nil {
		return nil, ErrRejected
	}
	jwks, e := op.get(p.metadata.JWKSURI, 128<<10)
	if e != nil {
		return nil, e
	}
	keys, e := matchingKey(jwks, header.KeyID)
	if e != nil {
		return nil, e
	}
	now := p.c.now().UTC()
	verifier := oidc.NewVerifier(p.config.Issuer, &oidc.StaticKeySet{PublicKeys: keys}, &oidc.Config{ClientID: p.config.ClientID, SupportedSigningAlgs: []string{oidc.RS256}, Now: func() time.Time { return now }})
	verified, e := verifier.Verify(op.ctx, raw)
	if e != nil {
		return nil, ErrRejected
	}
	if verified.Issuer != p.config.Issuer || !text(verified.Subject, 255) || subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(in.Nonce)) != 1 || len(verified.Audience) < 1 || len(verified.Audience) > 16 || (len(verified.Audience) > 1 && claims.AuthorizedParty != p.config.ClientID) || (claims.AuthorizedParty != "" && claims.AuthorizedParty != p.config.ClientID) {
		return nil, ErrRejected
	}
	issued, e := numericTime(claims.Issued)
	if e != nil || issued.After(now) || now.Sub(issued) > 5*time.Minute {
		return nil, ErrRejected
	}
	expiry, e := numericTime(claims.Expiry)
	if e != nil || !now.Before(expiry) || expiry.After(issued.Add(24*time.Hour)) {
		return nil, ErrRejected
	}
	if claims.NotBefore != "" {
		nbf, e := numericTime(claims.NotBefore)
		if e != nil || nbf.After(now) {
			return nil, ErrRejected
		}
	}
	var authenticated time.Time
	if claims.AuthTime != "" {
		authenticated, e = numericTime(claims.AuthTime)
		age := 24 * time.Hour
		if p.config.MaximumAuthenticationAge > 0 {
			age = p.config.MaximumAuthenticationAge
		}
		if e != nil || authenticated.After(issued) || authenticated.After(now) || now.Sub(authenticated) > age {
			return nil, ErrRejected
		}
	} else if p.config.MaximumAuthenticationAge > 0 {
		return nil, ErrRejected
	}
	if len(claims.AMR) > 16 || (claims.ACR != "" && !text(claims.ACR, 256)) {
		return nil, ErrRejected
	}
	for _, method := range claims.AMR {
		if !text(method, 128) {
			return nil, ErrRejected
		}
	}
	if verified.AccessTokenHash != "" {
		if len(token.AccessToken) > 64<<10 || verified.VerifyAccessToken(token.AccessToken) != nil {
			return nil, ErrRejected
		}
	}
	if op.ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return &VerifiedIdentity{verified: true, claims: Claims{Issuer: verified.Issuer, Subject: verified.Subject, ExpiresAt: expiry, IssuedAt: issued, AuthenticationTime: authenticated, ACR: claims.ACR, AMR: append([]string{}, claims.AMR...)}}, nil
}

type tokenClaims struct {
	AuthorizedParty string      `json:"azp"`
	Issued          numericDate `json:"iat"`
	Expiry          numericDate `json:"exp"`
	NotBefore       numericDate `json:"nbf"`
	AuthTime        numericDate `json:"auth_time"`
	ACR             string      `json:"acr"`
	AMR             []string    `json:"amr"`
}

// This profile accepts integer NumericDate values only; null, quoted numbers
// and fractional encodings cannot masquerade as an absent optional auth_time.
type numericDate string

func (n *numericDate) UnmarshalJSON(raw []byte) error {
	value, e := json.Number(string(raw)).Int64()
	if e != nil || value <= 0 {
		return ErrRejected
	}
	*n = numericDate(raw)
	return nil
}
func numericTime(n numericDate) (time.Time, error) {
	seconds, e := json.Number(n).Int64()
	if e != nil || seconds <= 0 {
		return time.Time{}, ErrRejected
	}
	return time.Unix(seconds, 0).UTC(), nil
}
func text(s string, limit int) bool {
	if s == "" || len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func matchingKey(raw []byte, kid string) ([]crypto.PublicKey, error) {
	keys, e := parseKeySet(raw)
	if e != nil {
		return nil, e
	}
	key, ok := keys[kid]
	if !ok {
		return nil, ErrRejected
	}
	return []crypto.PublicKey{key}, nil
}
func parseKeySet(raw []byte) (map[string]crypto.PublicKey, error) {
	var set jose.JSONWebKeySet
	if safeJSON(raw, &set) != nil || len(set.Keys) < 1 || len(set.Keys) > 32 {
		return nil, ErrUnavailable
	}
	seen := map[string]bool{}
	keys := map[string]crypto.PublicKey{}
	for _, key := range set.Keys {
		if !text(key.KeyID, 128) || seen[key.KeyID] {
			return nil, ErrUnavailable
		}
		seen[key.KeyID] = true
		if (key.Algorithm != "" && key.Algorithm != "RS256") || (key.Use != "" && key.Use != "sig") {
			continue
		}
		public, ok := key.Key.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if public.N == nil || public.N.BitLen() < 2048 || public.N.BitLen() > 8192 || public.E < 3 || public.E%2 == 0 {
			return nil, ErrUnavailable
		}
		keys[key.KeyID] = public
	}
	if len(keys) == 0 {
		return nil, ErrUnavailable
	}
	return keys, nil
}

// Unknown extension claims remain legal, while duplicate names, deep objects,
// giant arrays and trailing JSON cannot create verifier/claims parser ambiguity.
func safeJSON(raw []byte, out any) error {
	if !utf8.Valid(raw) {
		return ErrRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if e := walkJSON(decoder, 0); e != nil {
		return e
	}
	if _, e := decoder.Token(); e != io.EOF {
		return ErrRejected
	}
	if e := json.Unmarshal(raw, out); e != nil {
		return ErrRejected
	}
	return nil
}
func walkJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrRejected
	}
	token, e := d.Token()
	if e != nil {
		return ErrRejected
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			name, e := d.Token()
			key, ok := name.(string)
			if e != nil || !ok || seen[key] || len(seen) >= 256 {
				return ErrRejected
			}
			seen[key] = true
			if e = walkJSON(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		count := 0
		for d.More() {
			count++
			if count > 128 {
				return ErrRejected
			}
			if e = walkJSON(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return ErrRejected
	}
	if _, e = d.Token(); e != nil {
		return ErrRejected
	}
	return nil
}
