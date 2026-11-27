// Package deploymentplan implements immutable, pinned deployment-plan wire
// contracts. A valid signature establishes integrity and signer identity only;
// it is not evidence of approval, current authority, qualification or execution.
package deploymentplan

import (
	"errors"

	"github.com/netwizd/agp/internal/securityjournal"
)

const (
	Version1         = "agp.plan/v1alpha1"
	Version2         = "agp.plan/v1alpha2"
	FleetProfile     = "fleet-10k"
	SignedVersion    = "agp.signed-plan/v1alpha1"
	ExecutionPurpose = "execution"
	MaxPilotBytes    = 2 << 20
	MaxFleetBytes    = 32 << 20
	MaxEnvelopeBytes = MaxFleetBytes + 4096
)

var (
	ErrInvalid      = errors.New("deployment_plan_invalid")
	ErrUnauthorized = errors.New("deployment_plan_signature_rejected")
	ErrNotCurrent   = errors.New("deployment_plan_not_current")
)

type UInt63 = securityjournal.UInt63

// Plan contains complete resolved input and target pins. Slices representing
// sets are sorted by Normalize; it never mutates slices owned by its caller.
// CapacityProfile is absent in v1alpha1 and exactly fleet-10k in v1alpha2.
type Plan struct {
	APIVersion          string          `json:"apiVersion"`
	ID                  string          `json:"id"`
	Kind                string          `json:"kind"`
	SiteID              string          `json:"siteId"`
	RevisionID          string          `json:"revisionId"`
	CreatedBy           string          `json:"createdBy"`
	CreatedAt           string          `json:"createdAt"`
	ExpiresAt           string          `json:"expiresAt"`
	Targets             []Target        `json:"targets"`
	RolloutPolicy       RolloutPolicy   `json:"rolloutPolicy"`
	CompilerVersion     string          `json:"compilerVersion"`
	MinimumDenySequence UInt63          `json:"minimumDenySequence"`
	Reason              string          `json:"reason"`
	PlanDigest          string          `json:"planDigest"`
	ResolvedInputs      []ResolvedInput `json:"resolvedInputs"`
	AuthorityEpoch      UInt63          `json:"authorityEpoch"`
	CapacityProfile     string          `json:"capacityProfile,omitempty"`
}

type Target struct {
	NodeID                         string   `json:"nodeId"`
	BaseRevisionID                 string   `json:"baseRevisionId"`
	ExpectedNodeDeploymentSequence UInt63   `json:"expectedNodeDeploymentSequence"`
	CapabilityDigest               string   `json:"capabilityDigest"`
	BundleDigest                   string   `json:"bundleDigest"`
	SecretVersionIDs               []string `json:"secretVersionIds"`
	BaseBundleDigest               string   `json:"baseBundleDigest"`
}

type ResolvedInput struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type RolloutPolicy struct {
	CanaryNodeIDs      []string `json:"canaryNodeIds"`
	MaxParallel        int      `json:"maxParallel"`
	MaxUnavailable     int      `json:"maxUnavailable"`
	ObservationSeconds int      `json:"observationSeconds"`
	FailureAction      string   `json:"failureAction"`
}

// SignedPlan seals the full normalized Plan, including its recomputed digest.
// The envelope is purpose separated from manifests, permits and start proofs.
type SignedPlan struct {
	APIVersion string `json:"apiVersion"`
	Purpose    string `json:"purpose"`
	KeyID      string `json:"keyId"`
	Plan       Plan   `json:"plan"`
	Signature  string `json:"signature"`
}
