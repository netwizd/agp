package agentvalidation

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"

	"github.com/netwizd/agp/internal/configmodel"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// Decode rejects unknown/duplicate keys, trailing documents and oversized data.
// In particular, task/NodeBundle/argv/path/URL fields have no representation.
func Decode(r io.Reader) (*Request, error) {
	b, e := io.ReadAll(io.LimitReader(r, MaxRequestBytes+1))
	if e != nil || len(b) > MaxRequestBytes {
		return nil, ErrInvalid
	}
	if e = uniqueKeys(b); e != nil {
		return nil, e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return nil, ErrInvalid
	}
	for _, name := range []string{"apiVersion", "requestId", "authorityEpoch", "nodeDeploymentSequence", "capabilityDigest", "pins", "policy", "mode"} {
		if _, ok := fields[name]; !ok {
			return nil, ErrInvalid
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var in Request
	if d.Decode(&in) != nil {
		return nil, ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, ErrInvalid
	}
	if _, _, e = normalize(in); e != nil {
		return nil, e
	}
	return &in, nil
}

func uniqueKeys(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return ErrInvalid
		}
		t, e := d.Token()
		if e != nil {
			return ErrInvalid
		}
		if delimiter, ok := t.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return ErrInvalid
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return ErrInvalid
					}
					seen[s] = true
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return ErrInvalid
				}
			case '[':
				for d.More() {
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	return nil
}

func normalize(in Request) ([]byte, string, error) {
	if in.APIVersion != RequestVersion || !idPattern.MatchString(in.RequestID) || in.AuthorityEpoch == 0 || in.NodeDeploymentSequence != 0 || !configmodel.ValidDigest(in.CapabilityDigest) || (in.Mode != "detection" && in.Mode != "blocking") {
		return nil, "", ErrInvalid
	}
	for _, d := range []string{in.Pins.ManifestDigest, in.Pins.ProfileDigest, in.Pins.TupleDigest, in.Pins.EvidenceDigest, in.Pins.RendererDigest} {
		if !configmodel.ValidDigest(d) {
			return nil, "", ErrInvalid
		}
	}
	b, e := configmodel.CanonicalJSON(in.Policy)
	if e != nil || len(b) > MaxRequestBytes {
		return nil, "", ErrInvalid
	}
	p, e := configmodel.ParseWafPolicy(bytes.NewReader(b), configmodel.JSON)
	if e != nil {
		return nil, "", ErrInvalid
	}
	if len(p.Spec.Exceptions) != 0 {
		return nil, "", ErrUnsupported
	}
	in.Policy = *p
	b, e = configmodel.CanonicalJSON(in)
	if e != nil || len(b) > MaxRequestBytes {
		return nil, "", ErrInvalid
	}
	digest, e := configmodel.Digest(in)
	return b, digest, e
}
