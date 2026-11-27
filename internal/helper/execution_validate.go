package helper

import (
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/securityjournal"
)

func validateGeneration(g ExecutionGeneration) error {
	if !configmodel.ValidID(g.Baseline.RevisionID) || !configmodel.ValidID(g.GenerationID) || !configmodel.ValidDigest(g.Baseline.BundleDigest) || !configmodel.ValidDigest(g.TreeDigest) || !validCounters(g.Baseline.NodeDeploymentSequence) {
		return ErrState
	}
	return nil
}

func executionTargetMatches(g ExecutionGeneration, t Task) bool {
	return validateGeneration(g) == nil && g.Baseline.RevisionID == t.Payload.TargetRevisionID && g.Baseline.BundleDigest == t.Payload.BundleDigest && g.Baseline.NodeDeploymentSequence == t.NodeDeploymentSequence && g.GenerationID == t.Payload.DeploymentGeneration
}

func validateExecutionState(s ExecutionState, a ExecutionAnchor, digest string) error {
	i := a.Installation
	installationID, _ := installationDigest(i)
	receiptKey, keyErr := executionReceiptKey(a)
	if keyErr != nil {
		return ErrState
	}
	if s.APIVersion != ExecutionStateVersion || s.AnchorDigest != digest || validateGeneration(s.Active) != nil || validateGeneration(s.LastHealthy) != nil || s.Active != s.LastHealthy || s.HighWater < i.Baseline.NodeDeploymentSequence || s.Active.Baseline.NodeDeploymentSequence > s.HighWater || s.AuthorityEpoch < i.AuthorityEpoch || s.WriterEpoch < i.WriterEpoch || s.MinimumDenySequence < i.MinimumDenySequence || !validCounters(s.HighWater, s.AuthorityEpoch, s.WriterEpoch, s.MinimumDenySequence, s.ReceiptSequence) || s.Records == nil || len(s.Records) > MaxExecutionRecords {
		return ErrState
	}
	tasks, keys, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var previous, deploymentSequence UInt63
	deploymentSequence = i.Baseline.NodeDeploymentSequence
	for _, record := range s.Records {
		r := record.Receipt
		if r.NodeDeploymentSequence <= deploymentSequence {
			return ErrState
		}
		deploymentSequence = r.NodeDeploymentSequence
		if VerifyExecutionReceipt(r, a.ReceiptKeyID, receiptKey) != nil {
			return ErrState
		}
		if !idempotencyPattern.MatchString(record.IdempotencyKey) || !configmodel.ValidID(r.TaskID) || !configmodel.ValidID(r.ReceiptID) || tasks[r.TaskID] || keys[record.IdempotencyKey] || ids[r.ReceiptID] || r.APIVersion != ExecutionReceiptVersion || r.Purpose != "local_execution_outcome" || r.NodeID != i.NodeID || !configmodel.ValidDigest(r.RequestDigest) || r.NodeDeploymentSequence > s.HighWater || r.NodeDeploymentSequence <= i.Baseline.NodeDeploymentSequence || r.ReceiptSequence <= previous || r.ReceiptSequence > s.ReceiptSequence || r.ReceiptSequence > securityjournal.MaxUInt63 || validateGeneration(r.Active) != nil {
			return ErrState
		}
		if _, err := utc(r.RecordedAt); err != nil {
			return ErrState
		}
		switch r.State {
		case "succeeded", "failed", "recovered":
			if r.RecoveryRequired {
				return ErrState
			}
		case "recovery_required":
			if !r.RecoveryRequired {
				return ErrState
			}
		default:
			return ErrState
		}
		if r.Active.Baseline.NodeDeploymentSequence > r.NodeDeploymentSequence {
			return ErrState
		}
		if r.State == "succeeded" && r.Active.Baseline.NodeDeploymentSequence != r.NodeDeploymentSequence {
			return ErrState
		}
		tasks[r.TaskID], keys[record.IdempotencyKey], ids[r.ReceiptID] = true, true, true
		previous = r.ReceiptSequence
	}
	if previous != s.ReceiptSequence {
		return ErrState
	}
	if s.Attempt == nil {
		if s.RecoveryRequired || s.HighWater != deploymentSequence {
			return ErrState
		}
		if len(s.Records) == 0 {
			// A verified read-only baseline capture may durably raise security
			// floors without accepting work or advancing a deployment sequence.
			if s.Active.Baseline != i.Baseline {
				return ErrState
			}
		} else if s.Active != s.Records[len(s.Records)-1].Receipt.Active {
			return ErrState
		}
		return nil
	}
	at := s.Attempt
	t := at.Request.Task
	requestDigest, err := configmodel.Digest(at.Request)
	if err != nil || requestDigest != at.RequestDigest || validateRequest(at.Request) != nil || at.Request.SignedPlan == nil || deploymentplan.VerifyDigest(at.Request.SignedPlan.Plan) != nil || validateGeneration(at.Base) != nil || at.Base != s.Active || t.NodeID != i.NodeID || t.NodeDeploymentSequence != s.HighWater || t.Preconditions.ExpectedNodeDeploymentSequence != deploymentSequence || t.NodeDeploymentSequence <= deploymentSequence || t.Preconditions.BaseRevisionID != at.Base.Baseline.RevisionID || t.Payload.RecoveryBaseBundleDigest != at.Base.Baseline.BundleDigest || t.AuthorityEpoch != s.AuthorityEpoch || t.WriterEpoch != s.WriterEpoch || t.Payload.MinimumDenySequence > s.MinimumDenySequence || tasks[t.ID] || keys[t.IdempotencyKey] {
		return ErrState
	}
	if _, err := utc(at.AcceptedAt); err != nil {
		return ErrState
	}
	if at.AdmissionHead.AuthorityID != i.AuthorityID || at.AdmissionHead.Epoch != t.AuthorityEpoch || at.AdmissionHead.Sequence > s.MinimumDenySequence || at.AdmissionProof.Query.RequestDigest != at.RequestDigest || at.AdmissionProof.Query.InstallationDigest != installationID || at.AdmissionProof.Query.Head != pin(at.AdmissionHead) || at.AdmissionProof.WriterEpoch != t.WriterEpoch || !signatureShape(at.AdmissionProof.Signature) {
		return ErrState
	}
	if (at.EffectHead == nil) != (at.EffectProof == nil) {
		return ErrState
	}
	if at.EffectHead != nil && (at.EffectHead.AuthorityID != i.AuthorityID || at.EffectHead.Epoch != t.AuthorityEpoch || at.EffectHead.Sequence != s.MinimumDenySequence || at.EffectProof.Query.RequestDigest != at.RequestDigest || at.EffectProof.Query.InstallationDigest != installationID || at.EffectProof.Query.Head != pin(*at.EffectHead) || at.EffectProof.WriterEpoch != t.WriterEpoch || !signatureShape(at.EffectProof.Signature)) {
		return ErrState
	}
	switch at.Stage {
	case "preparing":
		if at.Target != nil || at.EffectHead != nil {
			return ErrState
		}
	case "prepared", "validated", "activating", "reloading", "verifying":
		if (at.Stage == "activating" || at.Stage == "reloading" || at.Stage == "verifying") && at.EffectHead == nil {
			return ErrState
		}
		if (at.Stage == "prepared" || at.Stage == "validated") && at.EffectHead != nil {
			return ErrState
		}
		if at.Target == nil || !executionTargetMatches(*at.Target, t) {
			return ErrState
		}
	case "recovery_required":
		if at.Target != nil && !executionTargetMatches(*at.Target, t) {
			return ErrState
		}
		if at.Containment == nil {
			return ErrState
		}
		c := at.Containment
		if c.Reason != "unverified_before_activation" && c.Reason != "unverified_after_activation" {
			return ErrState
		}
		if _, err := utc(c.RecordedAt); err != nil {
			return ErrState
		}
		switch c.State {
		case "pending", "succeeded":
			if c.ErrorCode != "" {
				return ErrState
			}
		case "failed":
			if c.ErrorCode != "containment_failed" {
				return ErrState
			}
		default:
			return ErrState
		}
	default:
		return ErrState
	}
	if at.Stage != "recovery_required" && at.Containment != nil {
		return ErrState
	}
	if at.Stage == "recovery_required" && !s.RecoveryRequired {
		return ErrState
	}
	return nil
}
