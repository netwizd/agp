package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/oidcclient"
	"github.com/netwizd/agp/internal/securityjournal"
)

var ErrOIDCInvalid = errors.New("invalid_oidc_request")
var ErrOIDCStale = errors.New("oidc_preconditions_changed")
var ErrOIDCReauthRequired = errors.New("oidc_step_up_required")

const OIDCDocumentLimit = 64 << 10

type OIDCProviderDocument struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   DirectoryMetadata `json:"metadata"`
	Spec       OIDCSpec          `json:"spec"`
}
type OIDCSpec struct {
	Issuer                   string       `json:"issuer"`
	AuthorizationEndpoint    string       `json:"authorizationEndpoint"`
	TokenEndpoint            string       `json:"tokenEndpoint"`
	JWKSURI                  string       `json:"jwksUri"`
	CASecretVersionID        string       `json:"caSecretVersionId"`
	ResponseType             string       `json:"responseType"`
	Scope                    string       `json:"scope"`
	TokenEndpointAuthMethod  string       `json:"tokenEndpointAuthMethod"`
	PKCEMethod               string       `json:"pkceMethod"`
	AllowedSigningAlgorithms []string     `json:"allowedSigningAlgorithms"`
	MFAClaimMode             string       `json:"mfaClaimMode"`
	IdentityBinding          string       `json:"identityBinding"`
	Clients                  []OIDCClient `json:"clients"`
}
type OIDCClient struct {
	Purpose                         string `json:"purpose"`
	ClientID                        string `json:"clientId"`
	ClientSecretVersionID           string `json:"clientSecretVersionId"`
	RedirectURI                     string `json:"redirectUri"`
	MaximumAuthenticationAgeSeconds int    `json:"maximumAuthenticationAgeSeconds"`
}
type OIDCProviderCreate struct {
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
}
type OIDCProviderView struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Issuer          string                 `json:"issuer"`
	SecurityGuardID string                 `json:"securityGuardId"`
	Revision        securityjournal.UInt63 `json:"revision"`
	Enabled         bool                   `json:"enabled"`
	Configuration   *OIDCProviderDocument  `json:"configuration"`
}
type OIDCProviderPage struct {
	Items      []OIDCProviderView `json:"items"`
	NextCursor string             `json:"nextCursor,omitempty"`
}
type OIDCVersionView struct {
	Configuration OIDCProviderDocument `json:"configuration"`
	ContentDigest string               `json:"contentDigest"`
}
type OIDCProviderTest struct {
	OperationID string `json:"operationId"`
	ProviderID  string `json:"providerId"`
	VersionID   string `json:"versionId"`
	State       string `json:"state"`
	ReasonCode  string `json:"reasonCode"`
}
type OIDCLinkVersion struct {
	ID                   string                 `json:"id"`
	LinkID               string                 `json:"linkId"`
	SecurityGuardVersion securityjournal.UInt63 `json:"securityGuardVersion"`
	DirectoryIdentityID  string                 `json:"directoryIdentityId"`
	PrincipalID          string                 `json:"principalId"`
	ContentDigest        string                 `json:"contentDigest,omitempty"`
}
type OIDCLinkView struct {
	ID              string                 `json:"id"`
	ProviderID      string                 `json:"providerId"`
	Subject         string                 `json:"subject"`
	SecurityGuardID string                 `json:"securityGuardId"`
	Revision        securityjournal.UInt63 `json:"revision"`
	Enabled         bool                   `json:"enabled"`
	Configuration   *OIDCLinkVersion       `json:"configuration"`
}
type OIDCLinkPage struct {
	Items      []OIDCLinkView `json:"items"`
	NextCursor string         `json:"nextCursor,omitempty"`
}
type OIDCLinkCreate struct {
	Subject             string    `json:"subject"`
	DirectoryIdentityID string    `json:"directoryIdentityId"`
	ExpiresAt           time.Time `json:"expiresAt"`
	Reason              string    `json:"reason"`
}
type OIDCLinkSuccessor struct {
	DirectoryIdentityID string    `json:"directoryIdentityId"`
	Enabled             bool      `json:"enabled"`
	ExpiresAt           time.Time `json:"expiresAt"`
	Reason              string    `json:"reason"`
}
type OIDCLinkChange struct {
	ProviderID                    string                 `json:"providerId"`
	ProviderVersionID             string                 `json:"providerVersionId"`
	ProviderGuardVersion          securityjournal.UInt63 `json:"providerGuardVersion"`
	LinkID                        string                 `json:"linkId"`
	VersionID                     string                 `json:"versionId"`
	ContentDigest                 string                 `json:"contentDigest"`
	GuardID                       string                 `json:"guardId"`
	PreviousGuardVersion          securityjournal.UInt63 `json:"previousGuardVersion"`
	NextGuardVersion              securityjournal.UInt63 `json:"nextGuardVersion"`
	Subject                       string                 `json:"subject"`
	DirectoryIdentityID           string                 `json:"directoryIdentityId"`
	DirectoryProviderVersionID    string                 `json:"directoryProviderVersionId"`
	DirectoryAuthenticatorVersion securityjournal.UInt63 `json:"directoryAuthenticatorVersion"`
	TargetPrincipalID             string                 `json:"targetPrincipalId"`
	ExpectedSecurityVersion       securityjournal.UInt63 `json:"expectedSecurityVersion"`
	ExpectedRowVersion            securityjournal.UInt63 `json:"expectedRowVersion"`
	ExpectedAuthorityEpoch        securityjournal.UInt63 `json:"expectedAuthorityEpoch"`
	Enabled                       bool                   `json:"enabled"`
	ExpiresAt                     time.Time              `json:"expiresAt"`
	Reason                        string                 `json:"reason"`
}
type OIDCSecurityOperation struct {
	ID             string                  `json:"id"`
	Family         string                  `json:"family"`
	RequestDigest  string                  `json:"requestDigest"`
	State          string                  `json:"state"`
	ApprovalStatus string                  `json:"approvalStatus"`
	SubjectID      string                  `json:"subjectId"`
	CreatedBy      string                  `json:"createdBy"`
	CreatedAt      time.Time               `json:"createdAt"`
	ProviderChange *ProviderSecurityChange `json:"providerChange,omitempty"`
	OIDCLinkChange *OIDCLinkChange         `json:"oidcLinkChange,omitempty"`
}

func oidcText(s string, max int) bool {
	if len(s) < 1 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func oidcHTTPS(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || u.String() != raw {
		return false
	}
	host, e := configmodel.CanonicalHostname(u.Hostname())
	if e != nil || host != u.Hostname() || u.Host != strings.ToLower(u.Host) {
		return false
	}
	if p := u.Port(); p != "" {
		v, e := strconv.Atoi(p)
		if e != nil || v < 1 || v > 65535 || v == 443 || strconv.Itoa(v) != p {
			return false
		}
	}
	return !strings.Contains(u.Path, "//") && (u.Path == "" || strings.TrimSuffix(u.Path, "/") == strings.TrimSuffix(path.Clean(u.Path), "/"))
}
func ParseOIDCProvider(r io.Reader) (*OIDCProviderDocument, error) {
	var d OIDCProviderDocument
	if configmodel.StrictJSON(r, &d, OIDCDocumentLimit) != nil {
		return nil, ErrOIDCInvalid
	}
	return normalizeOIDC(d)
}
func normalizeOIDC(d OIDCProviderDocument) (*OIDCProviderDocument, error) {
	m, s := d.Metadata, &d.Spec
	if d.APIVersion != "agp.identity/v1alpha1" || d.Kind != "OIDCProvider" || !configmodel.ValidID(m.ID) || !configmodel.ValidID(m.VersionID) || !configmodel.ValidID(m.SecurityGuardID) || m.SecurityGuardVersion == 0 || m.SecurityGuardVersion > securityjournal.MaxUInt63 {
		return nil, ErrOIDCInvalid
	}
	if !oidcHTTPS(s.Issuer) || !oidcHTTPS(s.AuthorizationEndpoint) || !oidcHTTPS(s.TokenEndpoint) || !oidcHTTPS(s.JWKSURI) || !configmodel.ValidID(s.CASecretVersionID) || s.ResponseType != "code" || s.Scope != "openid" || s.TokenEndpointAuthMethod != "client_secret_basic" || s.PKCEMethod != "S256" || s.MFAClaimMode != "none" || s.IdentityBinding != "approved_directory_link" || len(s.AllowedSigningAlgorithms) != 1 || s.AllowedSigningAlgorithms[0] != "RS256" || len(s.Clients) != 2 {
		return nil, ErrOIDCInvalid
	}
	s.Clients = append([]OIDCClient{}, s.Clients...)
	s.AllowedSigningAlgorithms = []string{"RS256"}
	sort.Slice(s.Clients, func(i, j int) bool { return s.Clients[i].Purpose < s.Clients[j].Purpose })
	if s.Clients[0].Purpose != "login" || s.Clients[1].Purpose != "management" || s.Clients[0].ClientID == s.Clients[1].ClientID || s.Clients[0].ClientSecretVersionID == s.Clients[1].ClientSecretVersionID {
		return nil, ErrOIDCInvalid
	}
	for _, c := range s.Clients {
		if !oidcText(c.ClientID, 256) || !configmodel.ValidID(c.ClientSecretVersionID) || c.ClientSecretVersionID == s.CASecretVersionID || !oidcHTTPS(c.RedirectURI) || c.MaximumAuthenticationAgeSeconds < 1 || c.MaximumAuthenticationAgeSeconds > 300 {
			return nil, ErrOIDCInvalid
		}
	}
	return &d, nil
}
func oidcDocument(d OIDCProviderDocument) (*OIDCVersionView, error) {
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, ErrOIDCInvalid
	}
	n, e := ParseOIDCProvider(bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	digest, e := configmodel.Digest(n)
	if e != nil {
		return nil, e
	}
	return &OIDCVersionView{Configuration: *n, ContentDigest: digest}, nil
}
func (d OIDCProviderDocument) client(purpose string) (oidcclient.Config, error) {
	for _, c := range d.Spec.Clients {
		if c.Purpose == purpose {
			return oidcclient.Config{Issuer: d.Spec.Issuer, ClientID: c.ClientID, ClientSecretVersionID: c.ClientSecretVersionID, CASecretVersionID: d.Spec.CASecretVersionID, Purpose: c.Purpose, RegisteredRedirectURIs: []string{c.RedirectURI}, MaximumAuthenticationAge: time.Duration(c.MaximumAuthenticationAgeSeconds) * time.Second, EndpointPins: oidcclient.EndpointPins{AuthorizationEndpoint: d.Spec.AuthorizationEndpoint, TokenEndpoint: d.Spec.TokenEndpoint, JWKSURI: d.Spec.JWKSURI}}, nil
		}
	}
	return oidcclient.Config{}, ErrOIDCInvalid
}
