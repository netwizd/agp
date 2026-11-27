package helper

import (
	"context"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
)

const (
	ExecutionAnchorVersion  = "agp.helper-execution-anchor/v1alpha1"
	ExecutionStateVersion   = "agp.helper-execution-state/v1alpha1"
	ExecutionReceiptVersion = "agp.helper-execution-receipt/v1alpha1"
	MaxExecutionRecords     = 1024
	MaxExecutionStateBytes  = MaxRequestBytes + (2 << 20)
)

// ExecutionAnchor is immutable installer input. LayoutDigest identifies the
// protected installed layout, separately from each generation's content tree.
type ExecutionAnchor struct {
	APIVersion       string       `json:"apiVersion"`
	Installation     Installation `json:"installation"`
	LayoutDigest     string       `json:"layoutDigest"`
	ReceiptKeyID     string       `json:"receiptKeyId"`
	ReceiptPublicKey string       `json:"receiptPublicKey"`
}

// ExecutionGeneration identifies verified local configuration AND the runtime
// generation serving it. A filesystem observation alone cannot establish this.
type ExecutionGeneration struct {
	Baseline     Baseline `json:"baseline"`
	GenerationID string   `json:"generationId"`
	TreeDigest   string   `json:"treeDigest"`
}

// ExecutionDriver is a trusted installer-selected adapter. Requests never supply
// paths, commands, service names, PIDs or probe URLs. Prepare durably preserves
// exactBase before creating the target. Snapshot and Verify include the complete
// protected tree and the actual running generation and functional probes.
// Activate must atomically compare current with exactBase, switch and fsync.
// Its context carries the short authorization deadline and must be checked
// immediately before the pointer mutation, after all potentially slow reads.
// Recover may restore ONLY the exact pre-authorized base preserved by Prepare.
type ExecutionDriver interface {
	Snapshot(context.Context) (ExecutionGeneration, error)
	Prepare(context.Context, Request, ExecutionGeneration) (ExecutionGeneration, error)
	Validate(context.Context, ExecutionGeneration) error
	Activate(context.Context, ExecutionGeneration, ExecutionGeneration) error
	Reload(context.Context, ExecutionGeneration) error
	Verify(context.Context, ExecutionGeneration) error
	Recover(context.Context, ExecutionGeneration, ExecutionGeneration) error
	// Contain stops or denies only the installed affected service when neither
	// target nor exact base can be proven healthy. It never claims recovery.
	Contain(context.Context) error
}

// ExecutionReceipt is immutable terminal local observation, not an admission
// receipt. Delivery failure never authorizes another effect or a rollback.
type ExecutionReceipt struct {
	APIVersion             string              `json:"apiVersion"`
	Purpose                string              `json:"purpose"`
	ReceiptID              string              `json:"receiptId"`
	ReceiptSequence        UInt63              `json:"receiptSequence"`
	NodeID                 string              `json:"nodeId"`
	TaskID                 string              `json:"taskId"`
	RequestDigest          string              `json:"requestDigest"`
	NodeDeploymentSequence UInt63              `json:"nodeDeploymentSequence"`
	Active                 ExecutionGeneration `json:"active"`
	State                  string              `json:"state"`
	RecoveryRequired       bool                `json:"recoveryRequired"`
	RecordedAt             string              `json:"recordedAt"`
	KeyID                  string              `json:"keyId"`
	Signature              string              `json:"signature"`
}

type ExecutionRecord struct {
	IdempotencyKey string           `json:"idempotencyKey"`
	Receipt        ExecutionReceipt `json:"receipt"`
	Delivered      bool             `json:"delivered"`
}

type ExecutionAttempt struct {
	Request        Request               `json:"request"`
	RequestDigest  string                `json:"requestDigest"`
	Base           ExecutionGeneration   `json:"base"`
	Target         *ExecutionGeneration  `json:"target,omitempty"`
	Stage          string                `json:"stage"`
	AcceptedAt     string                `json:"acceptedAt"`
	AdmissionHead  securityjournal.Head  `json:"admissionHead"`
	AdmissionProof StartProof            `json:"admissionProof"`
	EffectHead     *securityjournal.Head `json:"effectHead,omitempty"`
	EffectProof    *StartProof           `json:"effectProof,omitempty"`
	Containment    *ExecutionContainment `json:"containment,omitempty"`
}

type ExecutionContainment struct {
	Reason     string `json:"reason"`
	State      string `json:"state"`
	ErrorCode  string `json:"errorCode,omitempty"`
	RecordedAt string `json:"recordedAt"`
}

type ExecutionState struct {
	APIVersion          string              `json:"apiVersion"`
	AnchorDigest        string              `json:"anchorDigest"`
	Active              ExecutionGeneration `json:"active"`
	LastHealthy         ExecutionGeneration `json:"lastHealthy"`
	HighWater           UInt63              `json:"highWater"`
	AuthorityEpoch      UInt63              `json:"authorityEpoch"`
	WriterEpoch         UInt63              `json:"writerEpoch"`
	MinimumDenySequence UInt63              `json:"minimumDenySequence"`
	ReceiptSequence     UInt63              `json:"receiptSequence"`
	Attempt             *ExecutionAttempt   `json:"attempt,omitempty"`
	RecoveryRequired    bool                `json:"recoveryRequired"`
	Records             []ExecutionRecord   `json:"records"`
}

const executionTimeout = 2 * time.Minute
const executionRecoveryTimeout = 30 * time.Second

const executionContainmentTimeout = 10 * time.Second
