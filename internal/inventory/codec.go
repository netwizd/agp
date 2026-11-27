package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/netwizd/agp/internal/configmodel"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var labelPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)
var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func hash(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(b)
}
func Digest(v any) (string, error) {
	b, e := canonical(v)
	if e != nil {
		return "", e
	}
	return hash(b), nil
}

// Decode rejects duplicate keys, unknown fields, trailing documents and excess
// depth before decoding into the closed transport DTO.
func Decode(r io.Reader, out any) error { return decodeBounded(r, out, MaxObservationBytes) }
func decodeBounded(r io.Reader, out any, limit int64) error {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil || int64(len(b)) > limit || !utf8.Valid(b) {
		return ErrInvalid
	}
	if e = configmodel.ValidateJSON(b); e != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return ErrInvalid
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func safePath(s string) bool {
	return s != "" && len(s) <= 512 && !strings.ContainsAny(s, "\\\x00\r\n") && !strings.HasPrefix(s, "/") && path.Clean(s) == s && s != "." && s != ".." && !strings.HasPrefix(s, "../")
}
func boundedText(s string, n int) bool {
	return s != "" && len(s) <= n && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func normalizeObservation(in Observation) (Observation, []byte, []byte, error) {
	c := in.Capabilities
	if !bootPattern.MatchString(in.BootID) || uint64(in.FreeBytes) > uint64(^uint64(0)>>1) || c.ProtocolVersion != ProtocolVersion || !boundedText(c.AgentVersion, 64) || !boundedText(c.OS.ID, 64) || !boundedText(c.OS.VersionID, 64) || !boundedText(c.OS.Kernel, 128) || (c.OS.Architecture != "amd64" && c.OS.Architecture != "arm64") {
		return in, nil, nil, ErrInvalid
	}
	if c.Component != nil {
		cp := *c.Component
		cp.Files = append([]File(nil), cp.Files...)
		c.Component = &cp
		if !digestPattern.MatchString(cp.ProfileDigest) || len(cp.Files) == 0 || len(cp.Files) > 1000 {
			return in, nil, nil, ErrInvalid
		}
		sort.Slice(cp.Files, func(i, j int) bool { return cp.Files[i].Path < cp.Files[j].Path })
		for i, f := range cp.Files {
			if !safePath(f.Path) || !digestPattern.MatchString(f.Digest) || i > 0 && cp.Files[i-1].Path == f.Path {
				return in, nil, nil, ErrInvalid
			}
		}
	}
	in.Capabilities = c
	facts, e := canonical(c)
	if e != nil || len(facts) > 256<<10 {
		return in, nil, nil, ErrInvalid
	}
	b, e := canonical(in)
	if e != nil || len(b) > MaxObservationBytes {
		return in, nil, nil, ErrInvalid
	}
	return in, facts, b, nil
}
