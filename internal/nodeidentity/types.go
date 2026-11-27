// Package nodeidentity implements agent enrollment against an independent
// durable issuing authority. The control plane never receives a CA private key.
package nodeidentity

import (
	"context"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

var (
	ErrInvalid     = errors.New("invalid node identity request")
	ErrDenied      = errors.New("node identity rejected")
	ErrConflict    = errors.New("node identity conflict")
	ErrUnavailable = errors.New("node identity authority unavailable")
	ErrLimited     = errors.New("node identity rate limit")
)

type Current interface {
	Current(context.Context, func(storage.IdentityTx, securityjournal.Head) error) error
}
type Actor struct{ TokenHash, Origin string }
type CreateNodeRequest struct {
	ID       string            `json:"id"`
	SiteID   string            `json:"siteId"`
	Name     string            `json:"name"`
	Labels   map[string]string `json:"labels"`
	GroupIDs []string          `json:"groupIds,omitempty"`
}
type Node struct {
	ID        string            `json:"id"`
	SiteID    string            `json:"siteId"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	GroupIDs  []string          `json:"groupIds"`
	CreatedAt time.Time         `json:"createdAt"`
}
type EnrollmentRequest struct {
	Role       string `json:"role"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
}
type Enrollment struct {
	ID              string    `json:"id"`
	NodeID          string    `json:"nodeId"`
	Role            string    `json:"role"`
	State           string    `json:"state"`
	TokenAvailable  bool      `json:"tokenAvailable"`
	EnrollmentToken string    `json:"enrollmentToken,omitempty"`
	ExpiresAt       time.Time `json:"expiresAt"`
}
type EnrollmentSubmission struct {
	NodeID          string `json:"nodeId"`
	EnrollmentToken string `json:"enrollmentToken"`
	CSRPEM          string `json:"csrPem"`
}
type EnrollmentRequestView struct {
	ID              string    `json:"id"`
	EnrollmentID    string    `json:"enrollmentId"`
	NodeID          string    `json:"nodeId"`
	State           string    `json:"state"`
	PublicKeyDigest string    `json:"publicKeyDigest"`
	RequestDigest   string    `json:"requestDigest"`
	ExpiresAt       time.Time `json:"expiresAt"`
}
type ApprovalRequest struct {
	ExpectedPublicKeyDigest string `json:"expectedPublicKeyDigest"`
	RequestDigest           string `json:"requestDigest"`
}
type RenewalRequest struct {
	CSRPEM string `json:"csrPem"`
}
type CertificateResult struct {
	NodeID              string    `json:"nodeId"`
	Role                string    `json:"role"`
	CertificatePEM      string    `json:"certificatePem"`
	CertificateChainPEM string    `json:"certificateChainPem"`
	Serial              string    `json:"serial"`
	ExpiresAt           time.Time `json:"expiresAt"`
	PublicKeyDigest     string    `json:"publicKeyDigest"`
}

// Reservation burns one enrollment authorization to one CSR in the independent
// ledger. It does not issue a certificate until an operator approves this digest.
type Reservation struct {
	EnrollmentID  string                 `json:"enrollmentId"`
	TokenHash     string                 `json:"tokenHash"`
	Node          Node                   `json:"node"`
	Role          string                 `json:"role"`
	Epoch         securityjournal.UInt63 `json:"epoch"`
	CSRPEM        string                 `json:"csrPem"`
	RequestDigest string                 `json:"requestDigest"`
	ExpiresAt     time.Time              `json:"expiresAt"`
}

// AuthorizationHead binds a positive issuance to the exact independent security
// state used by the control plane's current approver check. A bare epoch cannot
// fence a concurrent principal restriction within that epoch.
type AuthorizationHead struct {
	AuthorityID string                 `json:"authorityId"`
	Epoch       securityjournal.UInt63 `json:"epoch"`
	Sequence    securityjournal.UInt63 `json:"sequence"`
	Digest      string                 `json:"digest"`
}

func authorizationHead(h securityjournal.Head) AuthorizationHead {
	return AuthorizationHead{AuthorityID: h.AuthorityID, Epoch: h.Epoch, Sequence: h.Sequence, Digest: h.Digest}
}
func (p AuthorizationHead) valid() bool {
	return idPattern.MatchString(p.AuthorityID) && p.Epoch > 0 && p.Epoch <= securityjournal.MaxUInt63 && p.Sequence <= securityjournal.MaxUInt63 && ((p.Sequence == 0 && p.Digest == "") || (p.Sequence > 0 && digestPattern.MatchString(p.Digest)))
}
func (p AuthorizationHead) matches(h securityjournal.Head) bool {
	return p.AuthorityID == h.AuthorityID && p.Epoch == h.Epoch && p.Sequence == h.Sequence && p.Digest == h.Digest
}

type IssueRequest struct {
	AuthorizationHead      AuthorizationHead `json:"authorizationHead"`
	Reservation            Reservation       `json:"reservation"`
	ApprovalDigest         string            `json:"approvalDigest"`
	AuthorizationExpiresAt *time.Time        `json:"authorizationExpiresAt,omitempty"`
}
type RenewRequest struct {
	NodeID            string                 `json:"nodeId"`
	CertificateDigest string                 `json:"certificateDigest"`
	CSRPEM            string                 `json:"csrPem"`
	Epoch             securityjournal.UInt63 `json:"epoch"`
}
type Issuer interface {
	inventory.RegistryProvider
	Reserve(context.Context, Reservation) error
	Issue(context.Context, IssueRequest) (CertificateResult, error)
	Cancel(context.Context, string, securityjournal.UInt63) error
	Renew(context.Context, RenewRequest) (CertificateResult, error)
}
