package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
)

var (
	ErrDirectoryInvalid     = errors.New("invalid_directory_request")
	ErrDirectoryStale       = errors.New("directory_preconditions_changed")
	ErrDirectoryUnavailable = errors.New("identity_provider_unavailable")
)

const DirectoryDocumentLimit = 1 << 20

var directoryUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type DirectoryProviderDocument struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   DirectoryMetadata `json:"metadata"`
	Spec       DirectorySpec     `json:"spec"`
}
type DirectoryMetadata struct {
	ID                   string                 `json:"id"`
	VersionID            string                 `json:"versionId"`
	SecurityGuardID      string                 `json:"securityGuardId"`
	SecurityGuardVersion securityjournal.UInt63 `json:"securityGuardVersion"`
}
type DirectorySpec struct {
	ForestGUID              string                  `json:"forestGuid"`
	DomainDNS               string                  `json:"domainDns"`
	Transport               string                  `json:"transport"`
	Endpoints               []DirectoryEndpoint     `json:"endpoints"`
	UserBaseDNs             []string                `json:"userBaseDns"`
	GroupBaseDNs            []string                `json:"groupBaseDns"`
	BindDN                  string                  `json:"bindDn"`
	BindSecretVersionID     string                  `json:"bindSecretVersionId"`
	CASecretVersionID       string                  `json:"caSecretVersionId"`
	LoginAttribute          string                  `json:"loginAttribute"`
	Provisioning            string                  `json:"provisioning"`
	GroupResolution         string                  `json:"groupResolution"`
	AccountCheck            string                  `json:"accountCheck"`
	OperationTimeoutSeconds int                     `json:"operationTimeoutSeconds"`
	MaximumGroups           int                     `json:"maximumGroups"`
	GroupMappings           []DirectoryGroupMapping `json:"groupMappings"`
}
type DirectoryEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}
type DirectoryGroupMapping struct {
	GroupObjectGUID string `json:"groupObjectGuid"`
	AccessGroupID   string `json:"accessGroupId"`
}

// ParseDirectoryProvider is the closed wire boundary. No password, caller test
// result, TLS bypass, referral switch or mutable secret alias is accepted.
func ParseDirectoryProvider(r io.Reader) (*DirectoryProviderDocument, error) {
	var d DirectoryProviderDocument
	if configmodel.StrictJSON(r, &d, DirectoryDocumentLimit) != nil {
		return nil, ErrDirectoryInvalid
	}
	return normalizeDirectory(d)
}
func normalizeDirectory(d DirectoryProviderDocument) (*DirectoryProviderDocument, error) {
	if d.APIVersion != "agp.identity/v1alpha1" || d.Kind != "DirectoryProvider" || !configmodel.ValidID(d.Metadata.ID) || !configmodel.ValidID(d.Metadata.VersionID) || !configmodel.ValidID(d.Metadata.SecurityGuardID) || d.Metadata.SecurityGuardVersion == 0 || d.Metadata.SecurityGuardVersion > securityjournal.MaxUInt63 {
		return nil, ErrDirectoryInvalid
	}
	s := &d.Spec
	if !directoryUUID.MatchString(s.ForestGUID) || s.ForestGUID == "00000000-0000-0000-0000-000000000000" || (s.Transport != "ldaps" && s.Transport != "starttls") || (s.LoginAttribute != "userPrincipalName" && s.LoginAttribute != "sAMAccountName") || (s.Provisioning != "preprovisioned" && s.Provisioning != "jit_unprivileged") || s.GroupResolution != "token_groups_security" || s.AccountCheck != "live_each_allow" || s.OperationTimeoutSeconds < 1 || s.OperationTimeoutSeconds > 10 || s.MaximumGroups < 1 || s.MaximumGroups > 10000 || !configmodel.ValidID(s.BindSecretVersionID) || !configmodel.ValidID(s.CASecretVersionID) || !directoryDN(s.BindDN) {
		return nil, ErrDirectoryInvalid
	}
	var err error
	s.DomainDNS, err = configmodel.CanonicalHostname(s.DomainDNS)
	if err != nil || !strings.Contains(s.DomainDNS, ".") {
		return nil, ErrDirectoryInvalid
	}
	if len(s.Endpoints) < 1 || len(s.Endpoints) > 8 {
		return nil, ErrDirectoryInvalid
	}
	s.Endpoints = append([]DirectoryEndpoint{}, s.Endpoints...)
	seen := map[DirectoryEndpoint]bool{}
	for i := range s.Endpoints {
		e := &s.Endpoints[i]
		e.Host, err = configmodel.CanonicalHostname(e.Host)
		if err != nil || !strings.Contains(e.Host, ".") || e.Port < 1 || e.Port > 65535 || seen[*e] {
			return nil, ErrDirectoryInvalid
		}
		seen[*e] = true
	}
	// Endpoint order is failover policy, not a semantic set.
	if s.UserBaseDNs, err = directoryDNSet(s.UserBaseDNs); err != nil {
		return nil, err
	}
	if s.GroupBaseDNs, err = directoryDNSet(s.GroupBaseDNs); err != nil {
		return nil, err
	}
	if len(s.GroupMappings) > 2000 || s.GroupMappings == nil {
		return nil, ErrDirectoryInvalid
	}
	s.GroupMappings = append([]DirectoryGroupMapping{}, s.GroupMappings...)
	sort.Slice(s.GroupMappings, func(i, j int) bool {
		if s.GroupMappings[i].GroupObjectGUID == s.GroupMappings[j].GroupObjectGUID {
			return s.GroupMappings[i].AccessGroupID < s.GroupMappings[j].AccessGroupID
		}
		return s.GroupMappings[i].GroupObjectGUID < s.GroupMappings[j].GroupObjectGUID
	})
	guids := map[string]bool{}
	for _, m := range s.GroupMappings {
		if !directoryUUID.MatchString(m.GroupObjectGUID) || !configmodel.ValidID(m.AccessGroupID) || guids[m.GroupObjectGUID] {
			return nil, ErrDirectoryInvalid
		}
		guids[m.GroupObjectGUID] = true
	}
	return &d, nil
}
func directoryDN(s string) bool {
	if s == "" || len(s) > 2048 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	_, err := ldap.ParseDN(s)
	return err == nil
}
func directoryDNSet(in []string) ([]string, error) {
	if len(in) < 1 || len(in) > 16 {
		return nil, ErrDirectoryInvalid
	}
	out := append([]string{}, in...)
	sort.Strings(out)
	parsed := []*ldap.DN{}
	for _, s := range out {
		if !directoryDN(s) {
			return nil, ErrDirectoryInvalid
		}
		dn, _ := ldap.ParseDN(s)
		for _, prior := range parsed {
			if prior.EqualFold(dn) {
				return nil, ErrDirectoryInvalid
			}
		}
		parsed = append(parsed, dn)
	}
	return out, nil
}
func directoryDocument(d DirectoryProviderDocument) (*DirectoryVersionView, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, ErrDirectoryInvalid
	}
	n, err := ParseDirectoryProvider(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	digest, err := configmodel.Digest(n)
	if err != nil {
		return nil, err
	}
	return &DirectoryVersionView{Configuration: *n, ContentDigest: digest}, nil
}

type DirectoryActor struct{ TokenHash, Origin string }
type DirectoryCreate struct {
	Name       string `json:"name"`
	ForestGUID string `json:"forestGuid"`
}
type DirectoryProviderView struct {
	ID              string                     `json:"id"`
	Name            string                     `json:"name"`
	Enabled         bool                       `json:"enabled"`
	Revision        securityjournal.UInt63     `json:"revision"`
	Configuration   *DirectoryProviderDocument `json:"configuration"`
	ForestGUID      string                     `json:"forestGuid"`
	SecurityGuardID string                     `json:"securityGuardId"`
}
type DirectoryProviderPage struct {
	Items      []DirectoryProviderView `json:"items"`
	NextCursor string                  `json:"nextCursor,omitempty"`
}
type DirectoryVersionView struct {
	Configuration DirectoryProviderDocument `json:"configuration"`
	ContentDigest string                    `json:"contentDigest"`
}
type DirectoryTestCheck struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	ReasonCode string `json:"reasonCode"`
}
type DirectoryTestResult struct {
	OperationID string               `json:"operationId"`
	State       string               `json:"state"`
	Checks      []DirectoryTestCheck `json:"checks"`
}
type DirectoryActivation struct {
	VersionID string `json:"versionId"`
	Enabled   bool   `json:"enabled"`
	Reason    string `json:"reason"`
}
