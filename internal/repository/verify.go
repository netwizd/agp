package repository

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var objectPattern = regexp.MustCompile(`^objects/[0-9a-f]{64}$`)
var manifestPattern = regexp.MustCompile(`^releases/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.json$`)

func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
func reject(what string) error { return fmt.Errorf("%w: %s", ErrUntrusted, what) }
func boundedJSON(raw []byte) error {
	return ValidateMetadataJSON(raw)
}
func strict(raw []byte, out any) error {
	return decodeMetadata(raw, out)
}
func decimal(s string) (uint64, error) {
	n, e := strconv.ParseUint(s, 10, 63)
	if e != nil || strconv.FormatUint(n, 10) != s {
		return 0, reject("noncanonical UInt63")
	}
	return n, nil
}
func sameVersion(version, previous int64, raw, old []byte) error {
	if version < 1 || version < previous || (version == previous && !bytes.Equal(raw, old)) {
		return reject("metadata rollback or equivocation")
	}
	return nil
}

// Verify implements an offline TUF refresh, followed independently by the
// release signature and complete CAS closure checks. No unverified bytes run.
func Verify(ctx context.Context, anchor Anchor, previous *State, in Input, now time.Time) (*VerifiedRelease, error) {
	now = now.UTC()
	if now.IsZero() || anchor.Platform != (Platform{"ubuntu", "24.04", "amd64"}) || len(in.RootUpdates) > 32 || !manifestPattern.MatchString(in.ManifestPath) || in.ReadObject == nil {
		return nil, reject("verification prerequisites")
	}
	if e := boundedJSON(anchor.Root); e != nil {
		return nil, e
	}
	root := anchor.Root
	if previous != nil {
		if previous.AnchorDigest != Hash(anchor.Root) || now.Before(previous.CheckedAt) || len(previous.Root) == 0 {
			return nil, reject("independent trust state or clock rollback")
		}
		root = previous.Root
	}
	trusted, e := trustedmetadata.New(root)
	if e != nil {
		return nil, reject("trusted root")
	}
	trusted.RefTime = now
	if previous != nil && trusted.Root.Signed.Version != previous.RootVersion {
		return nil, reject("root state mismatch")
	}
	for _, raw := range in.RootUpdates {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if e = boundedJSON(raw); e != nil {
			return nil, e
		}
		if _, e = trusted.UpdateRoot(raw); e != nil {
			return nil, reject("root rotation")
		}
		root = raw
	}
	if e = separateKeys(anchor, trusted.Root); e != nil {
		return nil, e
	}
	for _, raw := range [][]byte{in.Timestamp, in.Snapshot, in.Targets} {
		if e = boundedJSON(raw); e != nil {
			return nil, e
		}
	}
	stamp, e := trusted.UpdateTimestamp(in.Timestamp)
	if e != nil {
		return nil, reject("TUF timestamp")
	}
	snapshot, e := trusted.UpdateSnapshot(in.Snapshot, false)
	if e != nil {
		return nil, reject("TUF snapshot")
	}
	targets, e := trusted.UpdateTargets(in.Targets)
	if e != nil {
		return nil, reject("TUF targets")
	}
	// This initial client accepts explicitly listed top-level targets only.
	// Delegation is not silently treated as authority to a matching path.
	if targets.Signed.Delegations != nil {
		return nil, reject("unsupported delegated targets")
	}
	if previous != nil {
		for _, v := range []struct {
			n, old     int64
			raw, prior []byte
		}{
			{stamp.Signed.Version, previous.TimestampVersion, in.Timestamp, previous.Timestamp},
			{snapshot.Signed.Version, previous.SnapshotVersion, in.Snapshot, previous.Snapshot},
			{targets.Signed.Version, previous.TargetsVersion, in.Targets, previous.Targets},
		} {
			if e = sameVersion(v.n, v.old, v.raw, v.prior); e != nil {
				return nil, e
			}
		}
	}
	if e = verifyTarget(targets, in.ManifestPath, in.Manifest); e != nil {
		return nil, e
	}
	var manifest Manifest
	if e = strict(in.Manifest, &manifest); e != nil {
		return nil, e
	}
	m := manifest.Signed
	if m.APIVersion != "agp.release/v1alpha1" || !idPattern.MatchString(m.ReleaseID) || in.ManifestPath != "releases/"+m.ReleaseID+".json" || m.Platform != anchor.Platform || m.MinimumAgentProtocol != "agp.task/v1alpha1" || !idPattern.MatchString(m.CompatibilityProfile.ID) || !digestPattern.MatchString(m.CompatibilityProfile.Digest) || !digestPattern.MatchString(m.DependencyClosureDigest) || !digestPattern.MatchString(m.SBOMDigest) {
		return nil, reject("release contract or platform")
	}
	if m.CreatedAt.IsZero() || m.CreatedAt.After(now) || !m.ExpiresAt.After(now) || !m.ExpiresAt.After(m.CreatedAt) {
		return nil, reject("manifest time")
	}
	seq, e := decimal(m.Sequence)
	if e != nil {
		return nil, e
	}
	floor, e := decimal(m.SecurityFloor)
	if e != nil {
		return nil, e
	}
	minSeq, minFloor := anchor.MinimumSequence, anchor.SecurityFloor
	if previous != nil {
		minSeq = max(minSeq, previous.Sequence)
		minFloor = max(minFloor, previous.SecurityFloor)
		if seq == previous.Sequence && Hash(in.Manifest) != previous.ManifestDigest {
			return nil, reject("release sequence equivocation")
		}
	}
	if seq < minSeq || seq < minFloor || floor < minFloor || seq < floor || seq > math.MaxInt64 {
		return nil, reject("release security floor")
	}
	if e = verifyManifestSignatures(anchor, in.Manifest, manifest.Signatures); e != nil {
		return nil, e
	}
	if len(m.Artifacts) < 1 || len(m.Artifacts) > 1000 {
		return nil, reject("artifact count")
	}
	objects := map[string][]byte{}
	paths := map[string]bool{}
	var total uint64
	for _, a := range m.Artifacts {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		n, err := decimal(a.Length)
		if err != nil || n == 0 || n > MaxArtifactBytes || !objectPattern.MatchString(a.Path) || a.Path != "objects/"+a.SHA256 || a.MediaType == "" || len(a.MediaType) > 128 || paths[a.Path] {
			return nil, reject("artifact descriptor")
		}
		total += n
		if total > MaxReleaseBytes {
			return nil, reject("closure byte budget")
		}
		paths[a.Path] = true
		b, err := in.ReadObject(a.Path, int64(n))
		if err != nil || uint64(len(b)) != n || Hash(b) != "sha256:"+a.SHA256 {
			return nil, reject("artifact integrity")
		}
		if e = verifyTarget(targets, a.Path, b); e != nil {
			return nil, e
		}
		objects["sha256:"+a.SHA256] = append([]byte(nil), b...)
	}
	if _, ok := objects[m.CompatibilityProfile.Digest]; !ok {
		return nil, reject("missing profile")
	}
	if _, ok := objects[m.DependencyClosureDigest]; !ok {
		return nil, reject("missing dependency closure")
	}
	if _, ok := objects[m.SBOMDigest]; !ok {
		return nil, reject("missing SBOM")
	}
	if e = verifyClosure(m, objects); e != nil {
		return nil, e
	}
	expires := m.ExpiresAt
	for _, expiry := range []time.Time{trusted.Root.Signed.Expires, stamp.Signed.Expires, snapshot.Signed.Expires, targets.Signed.Expires} {
		if expiry.Before(expires) {
			expires = expiry
		}
	}
	state := State{AnchorDigest: Hash(anchor.Root), Root: append([]byte(nil), root...), Timestamp: append([]byte(nil), in.Timestamp...), Snapshot: append([]byte(nil), in.Snapshot...), Targets: append([]byte(nil), in.Targets...), RootVersion: trusted.Root.Signed.Version, TimestampVersion: stamp.Signed.Version, SnapshotVersion: snapshot.Signed.Version, TargetsVersion: targets.Signed.Version, Sequence: seq, SecurityFloor: floor, ManifestDigest: Hash(in.Manifest), CheckedAt: now}
	return &VerifiedRelease{Manifest: manifest, ManifestDigest: Hash(in.Manifest), ExpiresAt: expires, Next: state, objects: objects}, nil
}
func verifyTarget(targets *metadata.Metadata[metadata.TargetsType], path string, raw []byte) error {
	t, ok := targets.Signed.Targets[path]
	if !ok || t.Length != int64(len(raw)) || len(t.Hashes["sha256"]) != sha256.Size || t.VerifyLengthHashes(raw) != nil {
		return reject("TUF target integrity")
	}
	return nil
}
func separateKeys(a Anchor, root *metadata.Metadata[metadata.RootType]) error {
	if a.ReleaseThreshold < 1 || a.ReleaseThreshold > len(a.ReleaseKeys) || len(a.ReleaseKeys) > 8 {
		return reject("release key threshold")
	}
	roleOwners := map[string]string{}
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		policy, ok := root.Signed.Roles[role]
		if !ok || policy.Threshold < 1 || policy.Threshold > len(policy.KeyIDs) {
			return reject("TUF role threshold")
		}
		for _, id := range policy.KeyIDs {
			key, ok := root.Signed.Keys[id]
			if !ok {
				return reject("TUF role key")
			}
			public, err := key.ToPublicKey()
			if err != nil {
				return reject("TUF public key")
			}
			encoded, err := x509.MarshalPKIXPublicKey(public)
			if err != nil {
				return reject("TUF public key encoding")
			}
			fingerprint := Hash(encoded)
			if _, reused := roleOwners[fingerprint]; reused {
				return reject("TUF role keys must be distinct")
			}
			roleOwners[fingerprint] = role
		}
	}
	seen := map[string]bool{}
	for id, key := range a.ReleaseKeys {
		if !idPattern.MatchString(id) || len(key) != ed25519.PublicKeySize || seen[string(key)] {
			return reject("release key identity")
		}
		seen[string(key)] = true
		for _, tufKey := range root.Signed.Keys {
			public, err := tufKey.ToPublicKey()
			if tufPublic, ok := public.(ed25519.PublicKey); err == nil && ok && bytes.Equal(tufPublic, key) {
				return reject("release and TUF keys must differ")
			}
		}
	}
	return nil
}
func verifyManifestSignatures(a Anchor, raw []byte, signatures []Signature) error {
	if len(signatures) < 1 || len(signatures) > 8 {
		return reject("manifest signatures")
	}
	var envelope struct {
		Signed json.RawMessage `json:"signed"`
	}
	if e := json.Unmarshal(raw, &envelope); e != nil {
		return reject("manifest signed body")
	}
	payload, e := jsoncanonicalizer.Transform(envelope.Signed)
	if e != nil {
		return reject("JCS signed body")
	}
	valid, seen := 0, map[string]bool{}
	for _, sig := range signatures {
		if sig.Algorithm != "ed25519" || seen[sig.KeyID] {
			return reject("duplicate or invalid signature")
		}
		seen[sig.KeyID] = true
		key, ok := a.ReleaseKeys[sig.KeyID]
		decoded, err := base64.StdEncoding.Strict().DecodeString(sig.Signature)
		if !ok || err != nil || len(decoded) != ed25519.SignatureSize || !ed25519.Verify(key, payload, decoded) {
			return reject("independent release signature")
		}
		valid++
	}
	if valid < a.ReleaseThreshold {
		return reject("release signature threshold")
	}
	return nil
}

type ClosureEntry struct {
	Path   string `json:"path"`
	Length string `json:"length"`
	SHA256 string `json:"sha256"`
}
type DependencyClosure struct {
	APIVersion string         `json:"apiVersion"`
	Artifacts  []ClosureEntry `json:"artifacts"`
}

func verifyClosure(m ManifestBody, objects map[string][]byte) error {
	var closure DependencyClosure
	if e := strict(objects[m.DependencyClosureDigest], &closure); e != nil {
		return e
	}
	if closure.APIVersion != "agp.dependency-closure/v1alpha1" || len(closure.Artifacts) != len(m.Artifacts)-1 {
		return reject("incomplete dependency closure")
	}
	expected := map[string]Artifact{}
	for _, a := range m.Artifacts {
		if "sha256:"+a.SHA256 != m.DependencyClosureDigest {
			expected[a.Path] = a
		}
	}
	for _, entry := range closure.Artifacts {
		a, ok := expected[entry.Path]
		if !ok || a.Length != entry.Length || a.SHA256 != entry.SHA256 {
			return reject("dependency closure mismatch")
		}
		delete(expected, entry.Path)
	}
	if len(expected) != 0 {
		return reject("missing dependency")
	}
	return nil
}
