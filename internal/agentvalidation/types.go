// Package agentvalidation records agent-bound, Control Plane local syntax
// probes. A result is neither a remote task receipt nor permission to deploy.
package agentvalidation

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

const (
	RequestVersion  = "agp.agent-local-syntax/v1alpha1"
	ResultVersion   = "agp.agent-local-syntax-result/v1alpha1"
	MaxRequestBytes = 64 << 10
	MaxResultBytes  = 64 << 10
	RequestTTL      = 60 * time.Second
)

var (
	ErrInvalid     = errors.New("invalid_local_syntax_request")
	ErrConflict    = errors.New("local_syntax_request_conflict")
	ErrPending     = errors.New("local_syntax_result_indeterminate")
	ErrBusy        = errors.New("local_syntax_busy")
	ErrUnavailable = errors.New("local_syntax_unavailable")
	ErrStale       = errors.New("local_syntax_precondition_changed")
	ErrUnsupported = errors.New("local_syntax_operation_unsupported")
)

type Current interface {
	Current(context.Context, func(storage.IdentityTx, securityjournal.Head) error) error
}

type Agents interface {
	WithFreshAgent(context.Context, *tls.ConnectionState, func(storage.IdentityTx, securityjournal.Head, inventory.Node) error) error
}

// Pins select an exact independently signed release and its native evidence.
// They are not a compiler bundle or execution permit.
type Pins struct {
	ManifestDigest string `json:"manifestDigest"`
	ProfileDigest  string `json:"profileDigest"`
	TupleDigest    string `json:"tupleDigest"`
	EvidenceDigest string `json:"evidenceDigest"`
	RendererDigest string `json:"rendererDigest"`
}

type Request struct {
	APIVersion             string                 `json:"apiVersion"`
	RequestID              string                 `json:"requestId"`
	AuthorityEpoch         securityjournal.UInt63 `json:"authorityEpoch"`
	NodeDeploymentSequence securityjournal.UInt63 `json:"nodeDeploymentSequence"`
	CapabilityDigest       string                 `json:"capabilityDigest"`
	Pins                   Pins                   `json:"pins"`
	Policy                 configmodel.WafPolicy  `json:"policy"`
	Mode                   string                 `json:"mode"`
}

type Result struct {
	APIVersion             string                 `json:"apiVersion"`
	ID                     string                 `json:"id"`
	RequestID              string                 `json:"requestId"`
	NodeID                 string                 `json:"nodeId,omitempty"`
	AuthorityEpoch         securityjournal.UInt63 `json:"authorityEpoch"`
	NodeDeploymentSequence securityjournal.UInt63 `json:"nodeDeploymentSequence"`
	RequestDigest          string                 `json:"requestDigest"`
	IdentityDigest         string                 `json:"identityDigest,omitempty"`
	CapabilityDigest       string                 `json:"capabilityDigest"`
	PolicyDigest           string                 `json:"policyDigest"`
	Pins                   Pins                   `json:"pins"`
	State                  string                 `json:"state"`
	NativeSyntaxOnly       bool                   `json:"nativeSyntaxOnly"`
	ExecutionLocation      string                 `json:"executionLocation"`
	Isolation              string                 `json:"isolation"`
	CreatedAt              time.Time              `json:"createdAt"`
	RecordedAt             time.Time              `json:"recordedAt"`
	ErrorCode              string                 `json:"errorCode,omitempty"`
}
