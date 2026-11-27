// Package repository verifies offline component releases. It has no signing,
// installation, network download or data-plane execution capability.
package repository

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"
)

var ErrUntrusted = errors.New("untrusted_component_release")

const MaxMetadataBytes = 4 << 20
const MaxArtifactBytes = 256 << 20
const MaxReleaseBytes = 1 << 30

type Platform struct {
	OS        string `json:"os"`
	OSVersion string `json:"osVersion"`
	Arch      string `json:"arch"`
}
type ProfileRef struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}
type Artifact struct {
	Path      string `json:"path"`
	Length    string `json:"length"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"mediaType"`
}
type ManifestBody struct {
	APIVersion              string     `json:"apiVersion"`
	ReleaseID               string     `json:"releaseId"`
	Sequence                string     `json:"sequence"`
	CreatedAt               time.Time  `json:"createdAt"`
	ExpiresAt               time.Time  `json:"expiresAt"`
	Platform                Platform   `json:"platform"`
	CompatibilityProfile    ProfileRef `json:"compatibilityProfile"`
	MinimumAgentProtocol    string     `json:"minimumAgentProtocol"`
	SecurityFloor           string     `json:"securityFloor"`
	Artifacts               []Artifact `json:"artifacts"`
	DependencyClosureDigest string     `json:"dependencyClosureDigest"`
	SBOMDigest              string     `json:"sbomDigest"`
}
type Signature struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"sig"`
}
type Manifest struct {
	Signed     ManifestBody `json:"signed"`
	Signatures []Signature  `json:"signatures"`
}

// Anchor is supplied by the installation's independent trust administrator,
// never by a catalog, HTTP caller or the release being verified.
type Anchor struct {
	Root             []byte
	ReleaseKeys      map[string]ed25519.PublicKey
	ReleaseThreshold int
	Platform         Platform
	MinimumSequence  uint64
	SecurityFloor    uint64
}

// State lives outside the Control Plane database and its restore domain.
// Metadata bytes and their versions are kept together to reject equivocation
// as well as version rollback. Callers must durably commit Next before use.
// CheckedAt is the import-time lower bound, not a wall-clock authority.
type State struct {
	AnchorDigest     string          `json:"anchorDigest"`
	Root             json.RawMessage `json:"root"`
	Timestamp        json.RawMessage `json:"timestamp"`
	Snapshot         json.RawMessage `json:"snapshot"`
	Targets          json.RawMessage `json:"targets"`
	RootVersion      int64           `json:"rootVersion"`
	TimestampVersion int64           `json:"timestampVersion"`
	SnapshotVersion  int64           `json:"snapshotVersion"`
	TargetsVersion   int64           `json:"targetsVersion"`
	Sequence         uint64          `json:"sequence"`
	SecurityFloor    uint64          `json:"securityFloor"`
	ManifestDigest   string          `json:"manifestDigest"`
	CheckedAt        time.Time       `json:"checkedAt"`
}
type Input struct {
	RootUpdates  [][]byte
	Timestamp    []byte
	Snapshot     []byte
	Targets      []byte
	ManifestPath string
	Manifest     []byte
	// ReadObject must return bounded immutable bytes of exactly this CAS path.
	ReadObject func(string, int64) ([]byte, error)
}
type VerifiedRelease struct {
	Manifest       Manifest
	ManifestDigest string
	ExpiresAt      time.Time
	Next           State
	objects        map[string][]byte
}

// Object returns a private copy. A caller cannot mutate the verified closure.
func (v *VerifiedRelease) Object(digest string) ([]byte, bool) {
	b, ok := v.objects[digest]
	return append([]byte(nil), b...), ok
}
