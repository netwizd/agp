// Package rolloutexecution owns approved, persistent privileged execution.
// Authoring proposals are deliberately not an input to this service.
package rolloutexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

var (
	ErrInvalid     = errors.New("execution_invalid_request")
	ErrUnavailable = errors.New("execution_source_unavailable")
	ErrConflict    = errors.New("execution_conflict")
	ErrStale       = errors.New("execution_precondition_changed")
	ErrUnsupported = errors.New("execution_policy_unsupported")
)

type Actor struct{ TokenHash, Origin string }
type Current interface {
	Head(context.Context) (securityjournal.Head, error)
	Current(context.Context, func(storage.IdentityTx, securityjournal.Head) error) error
}

// AgentAuthenticator rechecks exact mTLS identity and registry/revocation in
// the caller's current transaction. It must not open another writer.
type AgentAuthenticator func(context.Context, storage.IdentityTx, securityjournal.Head, *tls.ConnectionState) (string, error)

// Sources is installed by trusted runtime wiring. Resolve must verify actual
// baseline capture, immutable qualified bundle bytes and the complete source
// closure. Recheck repeats current identity, ownership, capability, writer lease,
// release/secret/auth floors and exact baseline checks for a frozen target.
// These methods must not recursively open a writer or trust operator catalogs.
// Record may update a verified baseline only for independently bound healthy
// terminal outcomes; recovery_required is an unknown runtime, never a baseline.
type Sources interface {
	Resolve(context.Context, storage.IdentityTx, securityjournal.Head, Selection) (*Snapshot, error)
	Recheck(context.Context, storage.IdentityTx, securityjournal.Head, TargetSnapshot) error
	Record(context.Context, storage.IdentityTx, securityjournal.Head, TargetSnapshot, helper.ExecutionReceipt) error
}

type Selection struct {
	Kind       string   `json:"kind"`
	SiteID     string   `json:"siteId"`
	RevisionID string   `json:"revisionId"`
	NodeIDs    []string `json:"nodeIds"`
}
type TargetSnapshot struct {
	Installation         helper.Installation        `json:"installation"`
	Baseline             helper.ExecutionGeneration `json:"baseline"`
	AcceptedSequence     securityjournal.UInt63     `json:"acceptedSequence"`
	NodeGroupIDs         []string                   `json:"nodeGroupIds"`
	BundleDigest         string                     `json:"bundleDigest"`
	TargetTreeDigest     string                     `json:"targetTreeDigest"`
	DeploymentGeneration string                     `json:"deploymentGeneration"`
	SecretVersionIDs     []string                   `json:"secretVersionIds"`
	SourceDigest         string                     `json:"sourceDigest"`
	ReceiptKeyID         string                     `json:"receiptKeyId"`
	ReceiptPublicKey     string                     `json:"receiptPublicKey"`
}
type Snapshot struct {
	CompilerVersion string                         `json:"compilerVersion"`
	ResolvedInputs  []deploymentplan.ResolvedInput `json:"resolvedInputs"`
	Authors         []string                       `json:"authors"`
	Targets         []TargetSnapshot               `json:"targets"`
}
type Keys struct {
	PermitKeyID  string
	PermitKey    ed25519.PrivateKey
	ControlKeyID string
	ControlKey   ed25519.PrivateKey
}
type Create struct {
	SiteID     string                       `json:"siteId"`
	RevisionID string                       `json:"revisionId"`
	NodeIDs    []string                     `json:"nodeIds"`
	Policy     deploymentplan.RolloutPolicy `json:"rolloutPolicy"`
	Reason     string                       `json:"reason"`
	ExpiresAt  time.Time                    `json:"expiresAt"`
}
type Approval struct {
	ID             string    `json:"id"`
	PlanID         string    `json:"planId"`
	PlanDigest     string    `json:"planDigest"`
	ApprovedBy     string    `json:"approvedBy"`
	ApprovalDigest string    `json:"approvalDigest"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	MFAAt          time.Time `json:"mfaAt"`
}
type TaskView struct {
	ID       string                   `json:"id"`
	NodeID   string                   `json:"nodeId"`
	Sequence securityjournal.UInt63   `json:"nodeDeploymentSequence"`
	State    string                   `json:"state"`
	Receipt  *helper.ExecutionReceipt `json:"receipt,omitempty"`
}
type ExecutionPlan struct {
	Plan         deploymentplan.Plan `json:"plan"`
	State        string              `json:"state"`
	ParentPlanID string              `json:"parentPlanId,omitempty"`
	Approval     *Approval           `json:"approval,omitempty"`
	Tasks        []TaskView          `json:"tasks"`
	Current      bool                `json:"current"`
	Access       *Access             `json:"access,omitempty"`
}
type Access struct {
	Read     bool `json:"read"`
	Approve  bool `json:"approve"`
	Dispatch bool `json:"dispatch"`
	Cancel   bool `json:"cancel"`
	Rollback bool `json:"rollback"`
}
type DirectorySubjects interface {
	WithCurrentHistoricalSubjects(context.Context, []string, func(context.Context) error) error
}
