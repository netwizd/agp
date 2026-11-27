// Package securityjournal implements the independently stored, signed security
// authority. It contains no control-plane database or positive-grant replay.
package securityjournal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// UInt63 has a decimal-string wire representation, avoiding JSON float rounding.
type UInt63 uint64

const MaxUInt63 UInt63 = 1<<63 - 1

func (v UInt63) MarshalJSON() ([]byte, error) {
	if v > MaxUInt63 {
		return nil, errors.New("UInt63 overflow")
	}
	return json.Marshal(strconv.FormatUint(uint64(v), 10))
}
func (v *UInt63) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("UInt63 must be a decimal string")
	}
	n, e := strconv.ParseUint(s, 10, 63)
	if e != nil || strconv.FormatUint(n, 10) != s {
		return errors.New("invalid UInt63")
	}
	*v = UInt63(n)
	return nil
}

type Payload struct {
	PrincipalID     string `json:"principalId,omitempty"`
	AuthenticatorID string `json:"authenticatorId,omitempty"`
	MinimumVersion  UInt63 `json:"minimumVersion,omitempty"`
	SessionID       string `json:"sessionId,omitempty"`
	ResourceID      string `json:"resourceId,omitempty"`
	GrantID         string `json:"grantId,omitempty"`
	NodeID          string `json:"nodeId,omitempty"`
	OriginalEventID string `json:"originalEventId,omitempty"`
	NewEpoch        UInt63 `json:"newEpoch,omitempty"`
	// Restore cutoff is durable in the independent authority, never inferred from
	// the restored CP clock. A restore epoch is fenced until ReleaseAfter.
	RestoreCutoff time.Time `json:"restoreCutoff,omitempty"`
	ReleaseAfter  time.Time `json:"releaseAfter,omitempty"`
}

type Head struct {
	AuthorityID   string    `json:"authorityId"`
	Epoch         UInt63    `json:"authorityEpoch"`
	Sequence      UInt63    `json:"sequence"`
	Digest        string    `json:"digest"`
	Challenge     string    `json:"challenge"`
	RecordedAt    time.Time `json:"recordedAt"`
	KeyID         string    `json:"keyId"`
	Signature     string    `json:"signature"`
	RestoreCutoff time.Time `json:"restoreCutoff,omitempty"`
	ReleaseAfter  time.Time `json:"releaseAfter,omitempty"`
}

func (h Head) SameState(other Head) bool {
	return h.AuthorityID == other.AuthorityID && h.Epoch == other.Epoch && h.Sequence == other.Sequence && h.Digest == other.Digest && h.RestoreCutoff.Equal(other.RestoreCutoff) && h.ReleaseAfter.Equal(other.ReleaseAfter)
}

type AppendRequest struct {
	OperationID         string    `json:"operationId"`
	ExpectedEpoch       UInt63    `json:"expectedEpoch"`
	ExpectedSequence    UInt63    `json:"expectedSequence"`
	ExpectedDigest      string    `json:"expectedDigest"`
	Kind                string    `json:"kind"`
	TargetType          string    `json:"targetType"`
	TargetID            string    `json:"targetId"`
	ActorID             string    `json:"actorId"`
	AuthorizationDigest string    `json:"authorizationDigest"`
	ApproverID          string    `json:"approverId,omitempty"`
	ApprovalKeyID       string    `json:"approvalKeyId,omitempty"`
	ApprovalSignature   string    `json:"approvalSignature,omitempty"`
	RecordedAt          time.Time `json:"recordedAt"`
	Payload             Payload   `json:"payload"`
}

type Event struct {
	AuthorityID    string        `json:"authorityId"`
	ID             string        `json:"id"`
	Epoch          UInt63        `json:"authorityEpoch"`
	Sequence       UInt63        `json:"sequence"`
	Request        AppendRequest `json:"request"`
	RequestDigest  string        `json:"requestDigest"`
	PreviousDigest string        `json:"previousDigest"`
	Digest         string        `json:"digest"`
	RecordedAt     time.Time     `json:"recordedAt"`
	KeyID          string        `json:"keyId"`
	Signature      string        `json:"signature"`
}

type Authority interface {
	Head(context.Context) (Head, error)
	Append(context.Context, AppendRequest) (Event, error)
	Operation(context.Context, string) (Event, error)
	Events(context.Context, UInt63, int) ([]Event, error)
}

var (
	ErrConflict    = errors.New("journal conflict")
	ErrNotFound    = errors.New("journal operation not found")
	ErrUnavailable = errors.New("security authority unavailable")
	ErrInvalid     = errors.New("invalid journal message")
)

func bad(message string) error { return fmt.Errorf("%w: %s", ErrInvalid, message) }
