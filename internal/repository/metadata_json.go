package repository

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// ValidateMetadataJSON admits large inventories and TUF target maps within the
// repository's byte, depth and token budgets. Configuration's label/object
// limits do not apply to these maps. JCS rejects duplicate keys (including
// escaped spellings of the same key) and malformed Unicode independently.
func ValidateMetadataJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxMetadataBytes {
		return reject("metadata byte budget")
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !utf8.Valid(raw) {
		return reject("metadata object, UTF-8 or byte budget")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	depth, tokens := 0, 0
	for {
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return reject("malformed metadata")
		}
		tokens++
		if tokens > 200000 {
			return reject("metadata token budget")
		}
		if d, ok := token.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
			if depth > 32 {
				return reject("metadata depth budget")
			}
		}
	}
	if depth != 0 {
		return reject("malformed metadata")
	}
	if _, e := jsoncanonicalizer.Transform(raw); e != nil {
		return reject("duplicate keys or malformed metadata")
	}
	return nil
}

// metadataShape preserves exact JSON field names without applying the label
// restrictions of declarative Configuration maps to repository inventories.
// Requiredness and semantic references remain enforced by each verifier.
func metadataShape(value any, t reflect.Type) error {
	if reflect.PointerTo(t).Implements(reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()) {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		if value == nil {
			return reject("metadata null")
		}
		return metadataShape(value, t.Elem())
	}
	if value == nil {
		return reject("metadata null")
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return reject("metadata object shape")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := strings.SplitN(field.Tag.Get("json"), ",", 2)[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for key, v := range object {
			field, ok := fields[key]
			if !ok {
				return reject("unknown metadata field")
			}
			if e := metadataShape(v, field); e != nil {
				return e
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok || t.Key().Kind() != reflect.String {
			return reject("metadata map shape")
		}
		for _, v := range object {
			if e := metadataShape(v, t.Elem()); e != nil {
				return e
			}
		}
	case reflect.Slice:
		array, ok := value.([]any)
		if !ok {
			return reject("metadata array shape")
		}
		for _, v := range array {
			if e := metadataShape(v, t.Elem()); e != nil {
				return e
			}
		}
	}
	return nil
}

func decodeMetadata(raw []byte, out any) error {
	if e := ValidateMetadataJSON(raw); e != nil {
		return e
	}
	t := reflect.TypeOf(out)
	if t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() {
		return reject("metadata decoder target")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if e := decoder.Decode(&value); e != nil {
		return reject("malformed metadata")
	}
	if e := metadataShape(value, t.Elem()); e != nil {
		return e
	}
	if e := json.Unmarshal(raw, out); e != nil {
		return reject("metadata value type")
	}
	return nil
}
