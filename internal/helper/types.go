// Package helper provides admission and a separate opt-in execution foundation.
// Gate and Store remain admission-only: their receipts never authorize effects
// or claim runtime success. Executor requires its own durable execution ledger,
// installer-selected driver and signing identity. Its native/root qualification
// is separate from controlled-adapter tests; no public socket is provided here.
package helper

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/securityjournal"
)

const (
	InstallationVersion = "agp.helper-installation/v1alpha1"
	PermitVersion       = "agp.helper-permit/v1alpha1"
	StartVersion        = "agp.helper-start/v1alpha1"
	AdmissionVersion    = "agp.helper-admission/v1alpha1"
	StateVersion        = "agp.helper-state/v1alpha1"
	MaxRequestBytes     = deploymentplan.MaxPilotBytes + (64 << 10)
	MaxStateBytes       = MaxRequestBytes + (32 << 10)
	MaxPermitTTL        = 15 * time.Minute
	MaxStartTTL         = 15 * time.Second
)

var (
	ErrInvalid      = errors.New("helper_invalid_request")
	ErrUnauthorized = errors.New("helper_authorization_rejected")
	ErrStale        = errors.New("helper_precondition_changed")
	ErrConflict     = errors.New("helper_task_conflict")
	ErrPending      = errors.New("helper_reconciliation_required")
	ErrState        = errors.New("helper_state_unavailable")
	ErrBusy         = errors.New("helper_state_locked")
	ErrPlanRequired = errors.New("helper_signed_plan_required")
)

type UInt63 = securityjournal.UInt63

// Installation is trusted installer input, never part of an agent request.
// Digests are pins, not proof that the underlying ownership tree or native
// artifacts have been qualified. A future installer must verify those bytes.
type Installation struct {
	APIVersion             string   `json:"apiVersion"`
	NodeID                 string   `json:"nodeId"`
	SiteID                 string   `json:"siteId"`
	IdentityDigest         string   `json:"identityDigest"`
	OwnershipDigest        string   `json:"ownershipDigest"`
	CapabilityDigest       string   `json:"capabilityDigest"`
	ComponentProfileDigest string   `json:"componentProfileDigest"`
	ReleaseManifestDigest  string   `json:"releaseManifestDigest"`
	TupleDigest            string   `json:"tupleDigest"`
	CompilerDigest         string   `json:"compilerDigest"`
	TrustDigest            string   `json:"trustDigest"`
	AuthorityID            string   `json:"authorityId"`
	AuthorityEpoch         UInt63   `json:"authorityEpoch"`
	WriterEpoch            UInt63   `json:"writerEpoch"`
	MinimumDenySequence    UInt63   `json:"minimumDenySequence"`
	Baseline               Baseline `json:"baseline"`
}

type Baseline struct {
	RevisionID             string `json:"revisionId"`
	BundleDigest           string `json:"bundleDigest"`
	NodeDeploymentSequence UInt63 `json:"nodeDeploymentSequence"`
}

// Task is the apply_config/rollback_config subset of agp.task/v1alpha1.
// Unsupported task kinds cannot enter this foundation.
type Task struct {
	APIVersion             string        `json:"apiVersion"`
	ID                     string        `json:"id"`
	NodeID                 string        `json:"nodeId"`
	Kind                   string        `json:"kind"`
	IdempotencyKey         string        `json:"idempotencyKey"`
	AuthorityEpoch         UInt63        `json:"authorityEpoch"`
	WriterEpoch            UInt63        `json:"writerEpoch"`
	NodeDeploymentSequence UInt63        `json:"nodeDeploymentSequence"`
	IssuedAt               string        `json:"issuedAt"`
	ExpiresAt              string        `json:"expiresAt"`
	PlanID                 string        `json:"planId"`
	PlanDigest             string        `json:"planDigest"`
	PermitDigest           string        `json:"permitDigest"`
	Preconditions          Preconditions `json:"preconditions"`
	Payload                Payload       `json:"payload"`
}

type Preconditions struct {
	BaseRevisionID                 string `json:"baseRevisionId"`
	ExpectedNodeDeploymentSequence UInt63 `json:"expectedNodeDeploymentSequence"`
	CapabilityDigest               string `json:"capabilityDigest"`
}

type Payload struct {
	TargetRevisionID         string   `json:"targetRevisionId"`
	DeploymentGeneration     string   `json:"deploymentGeneration"`
	BundleDigest             string   `json:"bundleDigest"`
	SecretVersionIDs         []string `json:"secretVersionIds"`
	MinimumDenySequence      UInt63   `json:"minimumDenySequence"`
	RecoveryBaseBundleDigest string   `json:"recoveryBaseBundleDigest"`
}

// Permit binds the entire task (excluding its permitDigest to break the hash
// cycle) plus resolved installation/release/approval/recovery authorization.
// It does not replace future verification of the complete signed DeploymentPlan.
type Permit struct {
	APIVersion             string   `json:"apiVersion"`
	KeyID                  string   `json:"keyId"`
	TaskDigest             string   `json:"taskDigest"`
	InstallationDigest     string   `json:"installationDigest"`
	IdentityDigest         string   `json:"identityDigest"`
	OwnershipDigest        string   `json:"ownershipDigest"`
	ComponentProfileDigest string   `json:"componentProfileDigest"`
	ReleaseManifestDigest  string   `json:"releaseManifestDigest"`
	TupleDigest            string   `json:"tupleDigest"`
	CompilerDigest         string   `json:"compilerDigest"`
	Approval               Approval `json:"approval"`
	Recovery               Recovery `json:"recovery"`
	Signature              string   `json:"signature"`
}

type Approval struct {
	SiteID         string `json:"siteId"`
	CreatedBy      string `json:"createdBy"`
	ApprovedBy     string `json:"approvedBy"`
	ApprovalDigest string `json:"approvalDigest"`
}

type Recovery struct {
	BaseRevisionID      string `json:"baseRevisionId"`
	BaseBundleDigest    string `json:"baseBundleDigest"`
	OwnershipDigest     string `json:"ownershipDigest"`
	MinimumDenySequence UInt63 `json:"minimumDenySequence"`
}

type Request struct {
	Task       Task                       `json:"task"`
	Permit     Permit                     `json:"permit"`
	SignedPlan *deploymentplan.SignedPlan `json:"signedPlan,omitempty"`
}

type HeadPin struct {
	AuthorityID string `json:"authorityId"`
	Epoch       UInt63 `json:"authorityEpoch"`
	Sequence    UInt63 `json:"sequence"`
	Digest      string `json:"digest"`
}

// StartQuery is generated inside admission, not supplied by the agent.
// The future control authorizer must recheck node revoke status, plan/approval,
// current actor scopes/MFA, writer lease and release/security floors at this head.
type StartQuery struct {
	APIVersion         string  `json:"apiVersion"`
	Challenge          string  `json:"challenge"`
	RequestDigest      string  `json:"requestDigest"`
	InstallationDigest string  `json:"installationDigest"`
	Head               HeadPin `json:"head"`
}

// StartProof is a short-lived, purpose-separated signed assertion of those
// current checks. A saved permit alone cannot authorize a new admission.
type StartProof struct {
	Query       StartQuery `json:"query"`
	KeyID       string     `json:"keyId"`
	WriterEpoch UInt63     `json:"writerEpoch"`
	CheckedAt   string     `json:"checkedAt"`
	ExpiresAt   string     `json:"expiresAt"`
	Signature   string     `json:"signature"`
}

// Sources must use independently pinned transports in a future runtime.
// Responses are bounded/closed-decoded and cryptographically verified here;
// neither a transport success nor a caller's boolean is authorization.
type Sources interface {
	Head(context.Context, string) ([]byte, error)
	Authorize(context.Context, StartQuery) ([]byte, error)
}

type Trust struct {
	PermitKeyID  string
	PermitKey    ed25519.PublicKey
	ControlKeyID string
	ControlKey   ed25519.PublicKey
	JournalKeyID string
	JournalKey   ed25519.PublicKey
}

// Receipt is historical admission evidence only; never agp.receipt/v1alpha1.
type Receipt struct {
	APIVersion             string `json:"apiVersion"`
	TaskID                 string `json:"taskId"`
	NodeID                 string `json:"nodeId"`
	RequestDigest          string `json:"requestDigest"`
	NodeDeploymentSequence UInt63 `json:"nodeDeploymentSequence"`
	AuthorityEpoch         UInt63 `json:"authorityEpoch"`
	WriterEpoch            UInt63 `json:"writerEpoch"`
	State                  string `json:"state"`
	NoExecution            bool   `json:"noExecution"`
	RecordedAt             string `json:"recordedAt"`
}

type Intent struct {
	Request       Request              `json:"request"`
	RequestDigest string               `json:"requestDigest"`
	Head          securityjournal.Head `json:"head"`
	Proof         StartProof           `json:"proof"`
	Receipt       Receipt              `json:"receipt"`
}

type diskState struct {
	APIVersion          string  `json:"apiVersion"`
	InstallationDigest  string  `json:"installationDigest"`
	HighWater           UInt63  `json:"highWater"`
	AuthorityEpoch      UInt63  `json:"authorityEpoch"`
	WriterEpoch         UInt63  `json:"writerEpoch"`
	MinimumDenySequence UInt63  `json:"minimumDenySequence"`
	Intent              *Intent `json:"intent,omitempty"`
	RecoveryRequired    bool    `json:"recoveryRequired"`
}

type Status struct {
	HighWater   UInt63   `json:"highWater"`
	State       string   `json:"state"`
	NoExecution bool     `json:"noExecution"`
	Admission   *Receipt `json:"admission,omitempty"`
}
