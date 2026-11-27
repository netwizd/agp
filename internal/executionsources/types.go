// Package executionsources joins independently authenticated materialization,
// current inventory and root-held helper observations. It does not compile,
// qualify, install or execute native configuration.
package executionsources

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/nativeactivation"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

const (
	CatalogVersion         = "agp.execution-source-catalog/v1alpha1"
	MaterializationVersion = "agp.native-materialization/v1alpha1"
	MaterializationDomain  = "AGP-NATIVE-MATERIALIZATION-v1"
	BaselineFreshness      = 2 * time.Minute
	MaxCatalogBytes        = 96 << 20
)

var (
	ErrUnavailable = errors.New("trusted_execution_source_unavailable")
	ErrStale       = errors.New("trusted_execution_source_changed")
	ErrCapture     = errors.New("verified_baseline_capture_required")
)

type Current interface {
	Head(context.Context) (securityjournal.Head, error)
	Current(context.Context, func(storage.IdentityTx, securityjournal.Head) error) error
}

// LoadConfig must reread installation-owned pins on every operation. Keeping a
// cached positive result would hide revocation and replacement of trust input.
type LoadConfig func(context.Context) (Config, error)

type Config struct {
	APIVersion        string                 `json:"apiVersion"`
	WriterEpoch       securityjournal.UInt63 `json:"writerEpoch"`
	Bindings          []Binding              `json:"bindings"`
	QualificationKeys map[string]string      `json:"qualificationKeys"`
	Materials         []Materialization      `json:"materials"`
	SecretVersions    []SecretVersion        `json:"secretVersions"`
}

type Binding struct {
	Anchor helper.ExecutionAnchor  `json:"anchor"`
	Native nativeactivation.Config `json:"native"`
}

// SecretVersion is a protected external trust pin, not a CP catalog claim. Its
// digest identifies the immutable secret version bound by the qualification.
type SecretVersion struct {
	ID             string                 `json:"id"`
	SiteID         string                 `json:"siteId"`
	Digest         string                 `json:"digest"`
	AuthorityEpoch securityjournal.UInt63 `json:"authorityEpoch"`
	Revoked        bool                   `json:"revoked"`
}

type Materialization struct {
	Attestation Attestation             `json:"attestation"`
	Bundle      nativeactivation.Bundle `json:"bundle"`
}

// Attestation binds the complete canonical native bundle, not only a proposal
// digest or a successful syntax check. Only the independent qualifier holds the
// signing key. This package accepts installed public keys only.
type Attestation struct {
	APIVersion            string   `json:"apiVersion"`
	Purpose               string   `json:"purpose"`
	ID                    string   `json:"id"`
	NodeID                string   `json:"nodeId"`
	SiteID                string   `json:"siteId"`
	RevisionID            string   `json:"revisionId"`
	ConfigurationDigest   string   `json:"configurationDigest"`
	ResolvedSourceDigest  string   `json:"resolvedSourceDigest"`
	BundleDigest          string   `json:"bundleDigest"`
	BundleFileDigest      string   `json:"bundleFileDigest"`
	GenerationID          string   `json:"generationId"`
	TargetTreeDigest      string   `json:"targetTreeDigest"`
	CompilerVersion       string   `json:"compilerVersion"`
	CompilerDigest        string   `json:"compilerDigest"`
	RendererDigest        string   `json:"rendererDigest"`
	ProfileDigest         string   `json:"profileDigest"`
	ReleaseManifestDigest string   `json:"releaseManifestDigest"`
	TupleDigest           string   `json:"tupleDigest"`
	EvidenceDigest        string   `json:"evidenceDigest"`
	NativeReportDigest    string   `json:"nativeReportDigest"`
	HarnessDigest         string   `json:"harnessDigest"`
	SecretVersionIDs      []string `json:"secretVersionIds"`
	IssuedAt              string   `json:"issuedAt"`
	ExpiresAt             string   `json:"expiresAt"`
	KeyID                 string   `json:"keyId"`
	Signature             string   `json:"signature"`
}

type baselineRecord struct {
	AnchorDigest                           string
	BootDigest, CaptureID                  string
	Active                                 helper.ExecutionGeneration
	Accepted, Receipt, Epoch, Writer, Deny securityjournal.UInt63
	VerifiedAt                             time.Time
	Version                                int64
	Frozen                                 bool
	ProofKind, ProofID                     string
}

type trustedConfig struct {
	config   Config
	bindings map[string]Binding
	keys     map[string]ed25519.PublicKey
	secrets  map[string]SecretVersion
}
