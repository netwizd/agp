// Package configuration owns draft authoring and immutable desired snapshots.
// It has no data-plane write, reload, secret-value or deployment capability.
package configuration

import (
	"encoding/json"
	"errors"
	"github.com/netwizd/agp/internal/configmodel"
	"time"
)

var (
	ErrRevisionMismatch    = errors.New("revision_mismatch")
	ErrIdempotencyConflict = errors.New("idempotency_conflict")
	ErrInvalidRequest      = errors.New("invalid_request")
	ErrUnavailable         = errors.New("configuration_unavailable")
)

type Actor struct{ TokenHash, Origin string }
type Revision struct {
	ID             string               `json:"id"`
	BaseRevisionID string               `json:"baseRevisionId,omitempty"`
	ContentDigest  string               `json:"contentDigest"`
	ViewScope      string               `json:"viewScope"`
	Content        json.RawMessage      `json:"content,omitempty"`
	GatewayView    *configmodel.Gateway `json:"gatewayView,omitempty"`
	GatewayAccess  *GatewayAccess       `json:"gatewayAccess,omitempty"`
	ResourceView   *ResourceRouteView   `json:"resourceView,omitempty"`
	ResourceAccess *GatewayAccess       `json:"resourceAccess,omitempty"`
	State          string               `json:"state"`
	Revision       string               `json:"revision"`
}

type GatewayAccess struct {
	Read bool `json:"read"`
	Edit bool `json:"edit"`
}

type GatewaySummary struct {
	ID              string        `json:"id"`
	SiteID          string        `json:"siteId"`
	Name            string        `json:"name"`
	DeploymentState string        `json:"deploymentState"`
	Access          GatewayAccess `json:"access"`
}

type GatewayPage struct {
	RevisionID string           `json:"revisionId,omitempty"`
	Items      []GatewaySummary `json:"items"`
	NextCursor string           `json:"nextCursor,omitempty"`
}
type Draft struct {
	ID             string          `json:"id"`
	BaseRevisionID string          `json:"baseRevisionId,omitempty"`
	Revision       string          `json:"revision"`
	ContentDigest  string          `json:"contentDigest"`
	Content        json.RawMessage `json:"content"`
}
type GatewayChange struct {
	GatewayID string          `json:"gatewayId"`
	Content   json.RawMessage `json:"content"`
}
type CreateRevision struct {
	BaseRevisionID string                     `json:"baseRevisionId,omitempty"`
	Content        json.RawMessage            `json:"content,omitempty"`
	GatewayChange  *GatewayChange             `json:"gatewayChange,omitempty"`
	WafZoneChange  *configmodel.WafZoneChange `json:"wafZoneChange,omitempty"`
	ResourceChange *ResourceChange            `json:"resourceChange,omitempty"`
}

type ResourceChange struct {
	ResourceID string          `json:"resourceId"`
	GatewayID  string          `json:"gatewayId"`
	RouteID    string          `json:"routeId"`
	Content    json.RawMessage `json:"content"`
}

type ResourceRouteView struct {
	ResourceID   string            `json:"resourceId"`
	ResourceName string            `json:"resourceName"`
	GatewayID    string            `json:"gatewayId"`
	Route        configmodel.Route `json:"route"`
}

type ResourceRouteSummary struct {
	ResourceID   string        `json:"resourceId"`
	ResourceName string        `json:"resourceName"`
	GatewayID    string        `json:"gatewayId"`
	RouteID      string        `json:"routeId"`
	RouteName    string        `json:"routeName"`
	Hostname     string        `json:"hostname"`
	Path         string        `json:"path"`
	Access       GatewayAccess `json:"access"`
}

type ResourceRoutePage struct {
	RevisionID string                 `json:"revisionId,omitempty"`
	Items      []ResourceRouteSummary `json:"items"`
	NextCursor string                 `json:"nextCursor,omitempty"`
}
type CreateDraft struct {
	BaseRevisionID string          `json:"baseRevisionId,omitempty"`
	Content        json.RawMessage `json:"content"`
}
type RevisionPage struct {
	Items      []Revision `json:"items"`
	NextCursor string     `json:"nextCursor,omitempty"`
}
type CatalogSnapshot struct {
	ID            string    `json:"id"`
	ContentDigest string    `json:"contentDigest"`
	SourceKind    string    `json:"sourceKind"`
	SourceRef     string    `json:"sourceRef"`
	RecordedAt    time.Time `json:"recordedAt"`
}
type Profile struct {
	Enabled        bool   `json:"enabled"`
	HeadRevisionID string `json:"headRevisionId,omitempty"`
}
type AcceptedOperation struct {
	OperationID string    `json:"operationId"`
	ResourceID  string    `json:"resourceId"`
	StatusURL   string    `json:"statusUrl"`
	SubmittedAt time.Time `json:"submittedAt"`
}
type Operation struct {
	ID         string    `json:"id"`
	ResourceID string    `json:"resourceId"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}
