// Package inventory records bounded observations from externally provisioned,
// independently identified agents. Observations never authorize apply or prove
// that traffic is currently protected.
package inventory

import (
	"context"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

const (
	ProtocolVersion     = "agp.agent/v1alpha1"
	ChallengeTTL        = 60 * time.Second
	Freshness           = 120 * time.Second
	MaxObservationBytes = 1 << 20
)

var (
	ErrInvalid     = errors.New("invalid inventory document")
	ErrIdentity    = errors.New("agent identity rejected")
	ErrChallenge   = errors.New("inventory challenge rejected")
	ErrConflict    = errors.New("inventory request conflict")
	ErrNotFresh    = errors.New("current agent inventory required")
	ErrUnavailable = errors.New("inventory dependency unavailable")
)

type Current interface {
	Current(context.Context, func(storage.IdentityTx, securityjournal.Head) error) error
}
type Authority interface {
	Head(context.Context) (securityjournal.Head, error)
}

// Registry is installation-owned public configuration outside the CP database
// and its restore domain. This is external preregistration, not enrollment.
type Registry struct {
	APIVersion  string         `json:"apiVersion"`
	AuthorityID string         `json:"authorityId"`
	Nodes       []Registration `json:"nodes"`
}
type Registration struct {
	NodeID            string                 `json:"nodeId"`
	SiteID            string                 `json:"siteId"`
	Name              string                 `json:"name"`
	Labels            map[string]string      `json:"labels"`
	GroupIDs          []string               `json:"groupIds"`
	CertificatePEM    string                 `json:"certificatePem"`
	CertificateDigest string                 `json:"certificateDigest"`
	PublicKeyDigest   string                 `json:"publicKeyDigest"`
	IssuerDigest      string                 `json:"issuerDigest"`
	Serial            string                 `json:"serial"`
	IssuanceEpoch     securityjournal.UInt63 `json:"issuanceEpoch"`
	AcceptUntil       *time.Time             `json:"acceptUntil,omitempty"`
	Revoked           bool                   `json:"revoked,omitempty"`
}

type OS struct {
	ID           string `json:"id"`
	VersionID    string `json:"versionId"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
}
type File struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}
type Component struct {
	ProfileDigest string `json:"profileDigest"`
	Files         []File `json:"files"`
}
type Capabilities struct {
	AgentVersion    string     `json:"agentVersion"`
	ProtocolVersion string     `json:"protocolVersion"`
	OS              OS         `json:"os"`
	Component       *Component `json:"component,omitempty"`
}
type Observation struct {
	BootID       string                 `json:"bootId"`
	FreeBytes    securityjournal.UInt63 `json:"freeBytes"`
	Capabilities Capabilities           `json:"capabilities"`
}
type Challenge struct {
	ID        string    `json:"id"`
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type Submission struct {
	RequestID   string      `json:"requestId"`
	ChallengeID string      `json:"challengeId"`
	Challenge   string      `json:"challenge"`
	Observation Observation `json:"observation"`
}
type Receipt struct {
	ID                string                 `json:"id"`
	Sequence          securityjournal.UInt63 `json:"sequence"`
	RequestID         string                 `json:"requestId"`
	NodeID            string                 `json:"nodeId"`
	CapabilityDigest  string                 `json:"capabilityDigest"`
	ObservationDigest string                 `json:"observationDigest"`
	ReceivedAt        time.Time              `json:"receivedAt"`
	ExpiresAt         time.Time              `json:"expiresAt"`
}

// Node includes only observed capabilities. A component must additionally pass
// the consuming service's signed-profile verifier before use in resolution.
type Node struct {
	ID               string            `json:"id"`
	SiteID           string            `json:"siteId"`
	Name             string            `json:"name"`
	Labels           map[string]string `json:"labels"`
	GroupIDs         []string          `json:"groupIds"`
	IdentityDigest   string            `json:"identityDigest"`
	CapabilityDigest string            `json:"capabilityDigest"`
	Capabilities     Capabilities      `json:"capabilities"`
	ReceiptID        string            `json:"receiptId"`
	ReceivedAt       time.Time         `json:"receivedAt"`
	ExpiresAt        time.Time         `json:"expiresAt"`
}
type NodeView struct {
	ID               string            `json:"id"`
	SiteID           string            `json:"siteId"`
	Name             string            `json:"name"`
	Labels           map[string]string `json:"labels"`
	GroupIDs         []string          `json:"groupIds"`
	Connectivity     string            `json:"connectivity"`
	IdentityState    string            `json:"identityState"`
	CapabilityDigest string            `json:"capabilityDigest,omitempty"`
	LastSeenAt       *time.Time        `json:"lastSeenAt,omitempty"`
}
