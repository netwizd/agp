package executionsources

import (
	"bytes"
	"encoding/json"

	"github.com/netwizd/agp/internal/configmodel"
)

// DecodeConfig accepts a bounded closed installation catalog. Native.Config's
// historic exported field spelling participates in LayoutDigest and is retained
// exactly. It is not suitable for configmodel's restricted HTTP DTO decoder.
func DecodeConfig(raw []byte) (Config, error) {
	var c Config
	err := decodeCatalog(raw, &c)
	return c, err
}
func DecodeMaterials(raw []byte) ([]Materialization, error) {
	var m []Materialization
	err := decodeCatalog(raw, &m)
	if m == nil {
		return nil, ErrUnavailable
	}
	return m, err
}

func decodeCatalog(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxCatalogBytes {
		return ErrUnavailable
	}
	// Reuse the project's duplicate-key/Unicode/depth/cardinality validator.
	// Wrapping also permits the separate materialization file's top-level array.
	wrapped := make([]byte, 0, len(raw)+13)
	wrapped = append(wrapped, `{"document":`...)
	wrapped = append(wrapped, raw...)
	wrapped = append(wrapped, '}')
	if configmodel.ValidateJSON(wrapped) != nil {
		return ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrUnavailable
	}
	// Detect case-insensitive field aliases, missing required persisted fields,
	// invalid escaped Unicode and numeric coercion through an exact round trip.
	var value any
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return ErrUnavailable
	}
	a, e := configmodel.CanonicalJSON(value)
	if e != nil {
		return ErrUnavailable
	}
	b, e := configmodel.CanonicalJSON(out)
	if e != nil || !bytes.Equal(a, b) {
		return ErrUnavailable
	}
	return nil
}
