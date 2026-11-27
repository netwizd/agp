// Package configmodel implements the approved, closed declarative configuration
// contracts. Parsing, normalization and hashing never change runtime state.
package configmodel

type Configuration struct {
	APIVersion         string              `json:"apiVersion" v:"enum=agp.config/v1alpha1|agp.config/v1alpha2"`
	Kind               string              `json:"kind" v:"const=Configuration"`
	Metadata           Metadata            `json:"metadata"`
	Gateways           []Gateway           `json:"gateways" v:"max=10000"`
	ProfileAssignments []ProfileAssignment `json:"profileAssignments" v:"max=20000"`
	CapacityProfile    string              `json:"capacityProfile,omitempty" v:"const=fleet-10k"`
}
type Metadata struct {
	ID   string `json:"id" v:"id"`
	Name string `json:"name" v:"min=1,max=128"`
}
type GatewayMetadata struct {
	ID     string `json:"id" v:"id"`
	Name   string `json:"name" v:"min=1,max=128"`
	SiteID string `json:"siteId" v:"id"`
	Labels Labels `json:"labels"`
}
type Labels map[string]string
type Gateway struct {
	APIVersion string          `json:"apiVersion" v:"const=agp.config/v1alpha1"`
	Kind       string          `json:"kind" v:"const=Gateway"`
	Metadata   GatewayMetadata `json:"metadata"`
	Spec       GatewaySpec     `json:"spec"`
}
type GatewaySpec struct {
	Ownership           string        `json:"ownership" v:"enum=managed|adopted"`
	NodeSelector        NodeSelector  `json:"nodeSelector"`
	ComponentProfileRef Reference     `json:"componentProfileRef"`
	TLS                 GatewayTLS    `json:"tls"`
	Authorization       Authorization `json:"authorization"`
	WAF                 WAFBinding    `json:"waf"`
	Routes              []Route       `json:"routes" v:"min=1,max=1000"`
	Monitoring          Monitoring    `json:"monitoring"`
}
type NodeSelector struct {
	NodeIDs     []string `json:"nodeIds,omitempty" v:"min=1,max=500,ids"`
	MatchLabels *Labels  `json:"matchLabels,omitempty"`
}
type Reference struct {
	ID     string `json:"id" v:"id"`
	Digest string `json:"digest" v:"digest"`
}
type GatewayTLS struct {
	CertificateVersionID string `json:"certificateVersionId" v:"id"`
}
type Authorization struct {
	Mode        string `json:"mode" v:"const=central"`
	FailureMode string `json:"failureMode" v:"const=closed"`
}
type WAFBinding struct {
	Engine           string `json:"engine" v:"const=modsecurity"`
	PolicyRevisionID string `json:"policyRevisionId" v:"id"`
	Mode             string `json:"mode" v:"enum=off|detection|blocking"`
}
type Monitoring struct {
	Metrics bool `json:"metrics"`
	Logs    bool `json:"logs"`
}
type Route struct {
	ID              string   `json:"id" v:"id"`
	Name            string   `json:"name" v:"min=1,max=128"`
	Hostname        string   `json:"hostname" v:"min=1,max=253"`
	Path            string   `json:"path" v:"min=1,max=1024"`
	Upstream        Upstream `json:"upstream"`
	Access          Access   `json:"access"`
	WAFExceptionIDs []string `json:"wafExceptionIds" v:"max=100,ids"`
}
type Upstream struct {
	URL                   string      `json:"url" v:"min=1,max=2048"`
	ConnectTimeoutSeconds int         `json:"connectTimeoutSeconds" v:"min=1,max=60"`
	ReadTimeoutSeconds    int         `json:"readTimeoutSeconds" v:"min=1,max=3600"`
	TLS                   UpstreamTLS `json:"tls"`
}
type UpstreamTLS struct {
	Verify            bool   `json:"verify" v:"const=true"`
	ServerName        string `json:"serverName,omitempty" v:"min=1,max=253"`
	CASecretVersionID string `json:"caSecretVersionId,omitempty" v:"id"`
}
type Access struct {
	GroupIDs   []string `json:"groupIds" v:"min=1,max=100,ids"`
	AllowCIDRs []string `json:"allowCidrs" v:"max=100"`
}
type ProfileAssignment struct {
	ID                string `json:"id" v:"id"`
	ProfileRevisionID string `json:"profileRevisionId" v:"id"`
	ScopeType         string `json:"scopeType" v:"enum=global|site|node_group|node|route"`
	ScopeID           string `json:"scopeId,omitempty" v:"id"`
}
type PolicyProfile struct {
	APIVersion string          `json:"apiVersion" v:"const=agp.profile/v1alpha1"`
	Kind       string          `json:"kind" v:"const=PolicyProfile"`
	Metadata   ProfileMetadata `json:"metadata"`
	Spec       ProfileSpec     `json:"spec"`
}
type ProfileMetadata struct {
	ID     string `json:"id" v:"id"`
	Name   string `json:"name" v:"min=1,max=128"`
	SiteID string `json:"siteId,omitempty" v:"id"`
}
type ProfileSpec struct {
	Level        string    `json:"level" v:"enum=global|site|node_group|node|route"`
	Overrides    Overrides `json:"overrides"`
	LockedFields []string  `json:"lockedFields" v:"max=6"`
}
type Overrides struct {
	WAFMode               *string   `json:"wafMode,omitempty" v:"enum=off|detection|blocking"`
	AllowedGroupIDs       *[]string `json:"allowedGroupIds,omitempty" v:"min=1,max=100,ids"`
	AllowCIDRs            *[]string `json:"allowCidrs,omitempty" v:"max=100"`
	RequireMFA            *bool     `json:"requireMfa,omitempty"`
	ConnectTimeoutSeconds *int      `json:"connectTimeoutSeconds,omitempty" v:"min=1,max=60"`
	ReadTimeoutSeconds    *int      `json:"readTimeoutSeconds,omitempty" v:"min=1,max=3600"`
}
type WafZone struct {
	APIVersion string       `json:"apiVersion" v:"const=agp.waf-zone/v1alpha1"`
	Kind       string       `json:"kind" v:"const=WafZone"`
	Metadata   ZoneMetadata `json:"metadata"`
	Spec       ZoneSpec     `json:"spec"`
}
type ZoneMetadata struct {
	ID      string `json:"id" v:"id"`
	Name    string `json:"name" v:"min=1,max=128"`
	SiteID  string `json:"siteId" v:"id"`
	OwnerID string `json:"ownerId" v:"id"`
}
type ZoneSpec struct {
	PolicyRevisionID string         `json:"policyRevisionId" v:"id"`
	Mode             string         `json:"mode" v:"enum=detection|blocking"`
	Membership       ZoneMembership `json:"membership"`
	Reason           string         `json:"reason" v:"min=8,max=1024"`
}
type ZoneMembership struct {
	GatewayIDs  []string `json:"gatewayIds,omitempty" v:"min=1,max=10000,ids"`
	MatchLabels *Labels  `json:"matchLabels,omitempty"`
	SiteDefault *bool    `json:"siteDefault,omitempty" v:"const=true"`
}
type WafZoneResolution struct {
	APIVersion           string         `json:"apiVersion" v:"const=agp.waf-zone-resolution/v1alpha1"`
	Kind                 string         `json:"kind" v:"const=WafZoneResolution"`
	ID                   string         `json:"id" v:"id"`
	SiteID               string         `json:"siteId" v:"id"`
	ZoneRevisionID       string         `json:"zoneRevisionId" v:"id"`
	BaseConfigRevisionID string         `json:"baseConfigRevisionId" v:"id"`
	Action               string         `json:"action" v:"enum=reconcile|retire"`
	InventoryDigest      string         `json:"inventoryDigest" v:"digest"`
	CapacityProfile      string         `json:"capacityProfile" v:"enum=pilot-500|fleet-10k"`
	CreatedAt            string         `json:"createdAt" v:"utc"`
	ExpiresAt            string         `json:"expiresAt" v:"utc"`
	ResolutionDigest     string         `json:"resolutionDigest" v:"digest"`
	Members              []ZoneMember   `json:"members" v:"max=10000"`
	Conflicts            []ZoneConflict `json:"conflicts" v:"max=10000"`
}
type ZoneMember struct {
	GatewayID              string   `json:"gatewayId" v:"id"`
	RouteIDs               []string `json:"routeIds" v:"min=1,max=1000,ids"`
	NodeIDs                []string `json:"nodeIds" v:"max=500,ids"`
	SourceZoneRevisionID   string   `json:"sourceZoneRevisionId,omitempty" v:"id"`
	TargetZoneRevisionID   string   `json:"targetZoneRevisionId,omitempty" v:"id"`
	SourcePolicyRevisionID string   `json:"sourcePolicyRevisionId" v:"id"`
	TargetPolicyRevisionID string   `json:"targetPolicyRevisionId,omitempty" v:"id"`
	BaseBindingDigest      string   `json:"baseBindingDigest" v:"digest"`
	TargetBindingDigest    string   `json:"targetBindingDigest,omitempty" v:"digest"`
	Disposition            string   `json:"disposition" v:"enum=inherited|derived|conflict"`
}
type ZoneConflict struct {
	GatewayID                string   `json:"gatewayId" v:"id"`
	Code                     string   `json:"code" v:"enum=waf_zone_ambiguous|waf_zone_unassigned|waf_zone_replacement_required|waf_zone_site_mismatch|waf_zone_policy_not_published|waf_zone_base_exceptions|waf_zone_lineage_conflict|waf_zone_exception_expired|waf_zone_security_minimum|waf_zone_node_unresolved|waf_zone_capacity_exceeded"`
	Path                     string   `json:"path" v:"max=512"`
	Message                  string   `json:"message" v:"min=1,max=1024"`
	CandidateZoneRevisionIDs []string `json:"candidateZoneRevisionIds,omitempty" v:"min=1,max=100,ids"`
}
type WafZoneChange struct {
	APIVersion       string `json:"apiVersion" v:"const=agp.waf-zone-change/v1alpha1"`
	Kind             string `json:"kind" v:"const=WafZoneChange"`
	BaseRevisionID   string `json:"baseRevisionId" v:"id"`
	ZoneRevisionID   string `json:"zoneRevisionId" v:"id"`
	ResolutionID     string `json:"resolutionId" v:"id"`
	ResolutionDigest string `json:"resolutionDigest" v:"digest"`
	Reason           string `json:"reason" v:"min=8,max=1024"`
}

type Issue struct {
	Path     string `json:"path"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}
type ValidationError struct{ Issues []Issue }

func (e *ValidationError) Error() string {
	if len(e.Issues) == 0 {
		return "invalid configuration"
	}
	return e.Issues[0].Path + ": " + e.Issues[0].Code + ": " + e.Issues[0].Message
}

type Capacity struct {
	Profile                                          string
	MaxBytes, MaxGateways, MaxRoutes, MaxAssignments int
}

var Pilot = Capacity{"pilot-500", 2 << 20, 500, 500000, 1000}
var Fleet = Capacity{"fleet-10k", 64 << 20, 10000, 100000, 20000}

type Document struct {
	Configuration Configuration
	Canonical     []byte
	Digest        string
	Capacity      Capacity
}
