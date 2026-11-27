package deploymentplan

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"golang.org/x/text/unicode/norm"
)

var utcPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)

// Parse closed-decodes a complete plan and verifies, rather than repairs, its
// supplied digest. Parser diagnostics cannot expose caller field names or text.
func Parse(r io.Reader) (*Plan, error) {
	raw, err := bounded(r, MaxFleetBytes)
	if err != nil {
		return nil, ErrInvalid
	}
	var p Plan
	if configmodel.StrictJSON(bytes.NewReader(raw), &p, MaxFleetBytes) != nil {
		return nil, ErrInvalid
	}
	var presence struct {
		CapacityProfile json.RawMessage `json:"capacityProfile"`
	}
	if json.Unmarshal(raw, &presence) != nil || (p.APIVersion == Version1 && len(presence.CapacityProfile) != 0) || len(raw) > byteLimit(p) || VerifyDigest(p) != nil {
		return nil, ErrInvalid
	}
	return Normalize(p)
}

// ParseSigned checks the closed envelope and embedded digest; callers must
// still Verify with a separately trusted key and current time.
func ParseSigned(r io.Reader) (*SignedPlan, error) {
	raw, err := bounded(r, MaxEnvelopeBytes)
	if err != nil {
		return nil, ErrInvalid
	}
	var s SignedPlan
	if configmodel.StrictJSON(bytes.NewReader(raw), &s, MaxEnvelopeBytes) != nil || envelopeShape(s) != nil || VerifyDigest(s.Plan) != nil {
		return nil, ErrInvalid
	}
	var presence struct {
		Plan struct {
			CapacityProfile json.RawMessage `json:"capacityProfile"`
		} `json:"plan"`
	}
	if json.Unmarshal(raw, &presence) != nil || (s.Plan.APIVersion == Version1 && len(presence.Plan.CapacityProfile) != 0) || len(raw) > byteLimit(s.Plan)+4096 {
		return nil, ErrInvalid
	}
	p, err := Normalize(s.Plan)
	if err != nil {
		return nil, ErrInvalid
	}
	s.Plan = *p
	return &s, nil
}

func bounded(r io.Reader, max int) ([]byte, error) {
	if r == nil {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil || len(raw) > max {
		return nil, ErrInvalid
	}
	return raw, nil
}

func byteLimit(p Plan) int {
	if p.APIVersion == Version2 {
		return MaxFleetBytes
	}
	return MaxPilotBytes
}

func utc(s string) (time.Time, error) {
	if len(s) > 35 || !utcPattern.MatchString(s) {
		return time.Time{}, ErrInvalid
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 1 {
		return time.Time{}, ErrInvalid
	}
	return t, nil
}

// Normalize validates all schema and cross-field constraints and returns a
// detached canonical copy with PlanDigest recomputed. Existing PlanDigest is
// deliberately ignored when constructing a plan; use VerifyDigest on ingress.
// No universal plan TTL is imposed by this wire contract.
func Normalize(p Plan) (*Plan, error) {
	maxInputs := 1000
	switch p.APIVersion {
	case Version1:
		if p.CapacityProfile != "" {
			return nil, ErrInvalid
		}
	case Version2:
		if p.CapacityProfile != FleetProfile {
			return nil, ErrInvalid
		}
		maxInputs = 50000
	default:
		return nil, ErrInvalid
	}
	if p.Kind != "apply_config" && p.Kind != "rollback_config" && p.Kind != "upgrade_components" {
		return nil, ErrInvalid
	}
	for _, id := range []string{p.ID, p.SiteID, p.RevisionID, p.CreatedBy} {
		if !configmodel.ValidID(id) {
			return nil, ErrInvalid
		}
	}
	if p.AuthorityEpoch == 0 || p.AuthorityEpoch > securityjournal.MaxUInt63 || p.MinimumDenySequence > securityjournal.MaxUInt63 || len(p.Targets) < 1 || len(p.Targets) > 500 || len(p.ResolvedInputs) < 1 || len(p.ResolvedInputs) > maxInputs {
		return nil, ErrInvalid
	}
	created, e1 := utc(p.CreatedAt)
	expires, e2 := utc(p.ExpiresAt)
	if e1 != nil || e2 != nil || !expires.After(created) || !text(p.CompilerVersion, 1, 64) || !text(p.Reason, 8, 1024) {
		return nil, ErrInvalid
	}
	p.CreatedAt, p.ExpiresAt = created.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano)
	p.CompilerVersion, p.Reason = norm.NFC.String(p.CompilerVersion), norm.NFC.String(p.Reason)
	// Normalization itself may combine characters, so recheck semantic lengths.
	if !text(p.CompilerVersion, 1, 64) || !text(p.Reason, 8, 1024) {
		return nil, ErrInvalid
	}
	p.Targets = slices.Clone(p.Targets)
	nodes := make(map[string]bool, len(p.Targets))
	for i := range p.Targets {
		t := &p.Targets[i]
		if !configmodel.ValidID(t.NodeID) || !configmodel.ValidID(t.BaseRevisionID) || nodes[t.NodeID] || t.ExpectedNodeDeploymentSequence > securityjournal.MaxUInt63 || !configmodel.ValidDigest(t.CapabilityDigest) || !configmodel.ValidDigest(t.BundleDigest) || !configmodel.ValidDigest(t.BaseBundleDigest) || t.SecretVersionIDs == nil || len(t.SecretVersionIDs) > 100 {
			return nil, ErrInvalid
		}
		nodes[t.NodeID] = true
		t.SecretVersionIDs = slices.Clone(t.SecretVersionIDs)
		slices.Sort(t.SecretVersionIDs)
		for j, id := range t.SecretVersionIDs {
			if !configmodel.ValidID(id) || (j > 0 && id == t.SecretVersionIDs[j-1]) {
				return nil, ErrInvalid
			}
		}
	}
	slices.SortFunc(p.Targets, func(a, b Target) int { return strings.Compare(a.NodeID, b.NodeID) })
	r := &p.RolloutPolicy
	if validateRollout(*r, nodes) != nil {
		return nil, ErrInvalid
	}
	r.CanaryNodeIDs = slices.Clone(r.CanaryNodeIDs)
	slices.Sort(r.CanaryNodeIDs)
	p.ResolvedInputs = slices.Clone(p.ResolvedInputs)
	slices.SortFunc(p.ResolvedInputs, func(a, b ResolvedInput) int {
		if n := strings.Compare(a.Kind, b.Kind); n != 0 {
			return n
		}
		return strings.Compare(a.ID, b.ID)
	})
	for i, input := range p.ResolvedInputs {
		if !inputKind(input.Kind) || !configmodel.ValidID(input.ID) || !configmodel.ValidDigest(input.Digest) || (i > 0 && input.Kind == p.ResolvedInputs[i-1].Kind && input.ID == p.ResolvedInputs[i-1].ID) {
			return nil, ErrInvalid
		}
	}
	p.PlanDigest = ""
	raw, err := configmodel.CanonicalJSON(p)
	if err != nil || len(raw) > byteLimit(p) {
		return nil, ErrInvalid
	}
	p.PlanDigest = configmodel.DigestBytes(raw)
	raw, err = configmodel.CanonicalJSON(p)
	if err != nil || len(raw) > byteLimit(p) {
		return nil, ErrInvalid
	}
	return &p, nil
}

// ValidateRollout checks the shared rollout contract against a frozen exact
// target set. It has no effect on caller-owned slices and performs no approval.
func ValidateRollout(policy RolloutPolicy, targetIDs []string) error {
	if len(targetIDs) < 1 || len(targetIDs) > 500 {
		return ErrInvalid
	}
	nodes := make(map[string]bool, len(targetIDs))
	for _, id := range targetIDs {
		if !configmodel.ValidID(id) || nodes[id] {
			return ErrInvalid
		}
		nodes[id] = true
	}
	return validateRollout(policy, nodes)
}

func validateRollout(r RolloutPolicy, nodes map[string]bool) error {
	if len(r.CanaryNodeIDs) < 1 || len(r.CanaryNodeIDs) > 10 || r.MaxParallel < 1 || r.MaxParallel > 25 || r.MaxUnavailable < 0 || r.MaxUnavailable > 25 || r.ObservationSeconds < 30 || r.ObservationSeconds > 86400 || (r.FailureAction != "pause" && r.FailureAction != "rollback_wave") {
		return ErrInvalid
	}
	seen := make(map[string]bool, len(r.CanaryNodeIDs))
	for _, id := range r.CanaryNodeIDs {
		if !nodes[id] || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return nil
}

func text(s string, min, max int) bool {
	n := utf8.RuneCountInString(s)
	return utf8.ValidString(s) && n >= min && n <= max
}

func inputKind(s string) bool {
	switch s {
	case "access_policy", "waf_policy", "ruleset", "component_profile", "certificate", "policy_profile", "assignment_resolution":
		return true
	}
	return false
}

// Digest hashes the complete normalized plan with planDigest set to the empty
// string. No field is omitted; the empty self-field breaks the recursive hash.
func Digest(p Plan) (string, error) {
	n, err := Normalize(p)
	if err != nil {
		return "", ErrInvalid
	}
	return n.PlanDigest, nil
}

func VerifyDigest(p Plan) error {
	if !configmodel.ValidDigest(p.PlanDigest) {
		return ErrInvalid
	}
	d, err := Digest(p)
	if err != nil || d != p.PlanDigest {
		return ErrInvalid
	}
	return nil
}
