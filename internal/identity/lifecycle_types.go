package identity

import (
	"context"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

var (
	ErrLifecycleInvalid        = errors.New("identity_lifecycle_invalid")
	ErrLifecycleStale          = errors.New("identity_lifecycle_stale")
	ErrLifecycleUnavailable    = errors.New("identity_lifecycle_unavailable")
	ErrLifecycleReauthRequired = errors.New("identity_lifecycle_reauthentication_required")
)

// LifecycleActor identifies the authenticated request, never an asserted human.
// All authority is reloaded under the coordinator's current transaction.
type LifecycleActor struct{ TokenHash, Origin, SourceIP string }

type PendingUserInput struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	GroupIDs    []string `json:"groupIds"`
}
type LifecycleUserView struct {
	ID             string                 `json:"id"`
	Username       string                 `json:"username"`
	DisplayName    string                 `json:"displayName"`
	Blocked        bool                   `json:"blocked"`
	Privileged     bool                   `json:"privileged"`
	GroupIDs       []string               `json:"groupIds"`
	Revision       securityjournal.UInt63 `json:"revision"`
	LifecycleState string                 `json:"lifecycleState"`
}
type InviteRequest struct {
	Email      string `json:"email"`
	TTLSeconds int    `json:"ttlSeconds"`
}
type InviteView struct {
	InviteID            string    `json:"inviteId"`
	DeliveryOperationID string    `json:"deliveryOperationId"`
	ExpiresAt           time.Time `json:"expiresAt"`
}
type InviteDeliveryView struct {
	ID        string    `json:"id"`
	InviteID  string    `json:"inviteId"`
	State     string    `json:"state"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type PasswordResetRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}
type RecoveryPlanRequest struct {
	TargetPrincipalID       string                 `json:"targetPrincipalId"`
	ExpectedSecurityVersion securityjournal.UInt63 `json:"expectedSecurityVersion"`
	AllowedAction           string                 `json:"allowedAction"`
	ExpiresAt               time.Time              `json:"expiresAt"`
	Reason                  string                 `json:"reason"`
}
type RecoveryTicketView struct {
	Ticket    string    `json:"ticket"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// These private lifecycle interfaces permit Service to compile independently
// of the two implementations while keeping pending-principal exceptions typed.
// No HTTP input can select an allowPending mode or mint a flow authorization.
type activationLifecycle interface {
	StartActivate(context.Context, string, string, string, string) (Transition, error)
	BindInvitation(context.Context, FlowAuth, string, string) (Transition, error)
	SetInitialPassword(context.Context, FlowAuth, string) (FlowView, error)
	StartActivationEnrollment(context.Context, FlowAuth) (Enrollment, error)
	ConfirmActivationEnrollment(context.Context, FlowAuth, string, string) (EnrollmentResult, error)
	CompleteActivation(context.Context, FlowAuth) (Completion, error)
	EmailContactTx(context.Context, storage.IdentityTx, securityjournal.Head, *flow) (string, error)
	ConfirmEmailTx(context.Context, storage.IdentityTx, securityjournal.Head, *flow, string) error
	QueueEmailTokenTx(context.Context, storage.IdentityTx, securityjournal.Head, *lifecycleToken, string) (InviteView, error)
	CheckFlowTx(context.Context, storage.IdentityTx, securityjournal.Head, *flow) error
	CancelActivation(context.Context, FlowAuth) (FlowView, error)
	CancelPrincipalTx(context.Context, storage.IdentityTx, string) error
	CancelFlowTx(context.Context, storage.IdentityTx, string) error
	CleanupTx(context.Context, storage.IdentityTx, securityjournal.Head) error
}
type recoveryLifecycle interface {
	WithMFAReplacementPeople(context.Context, FlowAuth, func(context.Context) error) error
	CompleteMFAReplacement(context.Context, FlowAuth) (Completion, error)
	IsPasswordResetTx(context.Context, storage.IdentityTx, string) (bool, error)
	BindResetInvitation(context.Context, FlowAuth, string, string) (Transition, error)
	ConsumeSupervisedTicket(context.Context, FlowAuth, string, string) (Transition, error)
	VerifyResetTOTP(context.Context, FlowAuth, string) (FlowView, error)
	SetResetPassword(context.Context, FlowAuth, string) (FlowView, error)
	CompletePasswordReset(context.Context, FlowAuth) (Completion, error)
	CheckFlowTx(context.Context, storage.IdentityTx, securityjournal.Head, *flow) error
	AuthorizeLegacyMFAReplacementTx(context.Context, storage.IdentityTx, securityjournal.Head, *flow) error
	CancelRecovery(context.Context, FlowAuth) (FlowView, error)
	AllowMFAReplacementTx(context.Context, storage.IdentityTx, securityjournal.Head, *flow) error
	CancelFlowTx(context.Context, storage.IdentityTx, string) error
	CleanupTx(context.Context, storage.IdentityTx, securityjournal.Head) error
}

type lifecycleToken struct {
	ID, PrincipalID, Purpose, ProofKind, TokenHash        string
	GuardID                                               string
	GuardVersion, Epoch, SecurityVersion, PasswordVersion uint64
	PolicyDigest, IssuerID, IssuerFingerprint, ContactID  string
	ContactVersion, Generation                            uint64
	AuthorizationOperationID, AllowedAction               string
	CreatedAt, ExpiresAt                                  time.Time
	ReservedFlowID, ReservedBindingHash                   string
	ReservedAt, ConsumedAt, RevokedAt                     *time.Time
}
