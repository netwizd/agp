package helper

import (
	"slices"
	"time"

	"github.com/netwizd/agp/internal/deploymentplan"
)

// checkPlan binds the selected frozen target to this narrow task and installed
// component profile. Literal plan schemas do not bind all execution pins yet:
// the permit additionally binds compiler/release/tuple/identity/ownership. This
// admission-only package cannot establish full approval closure or qualification.
func checkPlan(r Request, i Installation, trust Trust, now time.Time) error {
	if r.SignedPlan == nil {
		return ErrPlanRequired
	}
	if deploymentplan.Verify(*r.SignedPlan, trust.PermitKeyID, trust.PermitKey, now) != nil {
		return ErrUnauthorized
	}
	p, t := r.SignedPlan.Plan, r.Task
	// The first helper contract supports the bounded pilot plan. Fleet-size
	// schemas can be parsed by deploymentplan, but require separate node budgets.
	if p.APIVersion != deploymentplan.Version1 || p.ID != t.PlanID || p.PlanDigest != t.PlanDigest || p.Kind != t.Kind || p.SiteID != i.SiteID || p.RevisionID != t.Payload.TargetRevisionID || p.CreatedBy != r.Permit.Approval.CreatedBy || p.AuthorityEpoch != t.AuthorityEpoch || t.Payload.MinimumDenySequence < p.MinimumDenySequence {
		return ErrStale
	}
	created, e1 := utc(p.CreatedAt)
	expires, e2 := utc(p.ExpiresAt)
	issued, e3 := utc(t.IssuedAt)
	taskExpires, e4 := utc(t.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || issued.Before(created) || taskExpires.After(expires) {
		return ErrStale
	}
	profile := false
	for _, input := range p.ResolvedInputs {
		if input.Kind == "component_profile" && input.Digest == i.ComponentProfileDigest {
			profile = true
		}
	}
	if !profile {
		return ErrStale
	}
	for _, target := range p.Targets {
		if target.NodeID != t.NodeID {
			continue
		}
		secrets := slices.Clone(target.SecretVersionIDs)
		slices.Sort(secrets)
		taskSecrets := slices.Clone(t.Payload.SecretVersionIDs)
		slices.Sort(taskSecrets)
		if target.BaseRevisionID != t.Preconditions.BaseRevisionID || target.BaseBundleDigest != t.Payload.RecoveryBaseBundleDigest || target.CapabilityDigest != t.Preconditions.CapabilityDigest || target.BundleDigest != t.Payload.BundleDigest || target.ExpectedNodeDeploymentSequence != t.Preconditions.ExpectedNodeDeploymentSequence || !slices.Equal(secrets, taskSecrets) {
			return ErrStale
		}
		return nil
	}
	return ErrStale
}
