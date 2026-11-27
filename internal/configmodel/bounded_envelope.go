package configmodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"
)

// DecodeEnvelopeJSONWithArrayLimits preserves the closed-field, duplicate-key,
// Unicode and depth checks of DecodeEnvelopeJSON. Only explicitly named arrays
// receive a different bounded capacity; callers still bound the complete bytes.
// Ordinary HTTP envelopes retain their original budgets.
func DecodeEnvelopeJSONWithArrayLimits(data []byte, dst any, limits map[string]int) error {
	for path, limit := range limits {
		if !strings.HasPrefix(path, "/") || limit < 1 || limit > 131072 {
			return fmt.Errorf("invalid envelope array capacity")
		}
	}
	if !utf8.Valid(data) {
		return problem("", "invalid_utf8", "valid UTF-8 required")
	}
	if e := validEscapedUnicode(data); e != nil {
		return e
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return problem("", "object_required", "one JSON object required")
	}
	if e := jsonPreflightWithArrayLimits(data, len(data), limits); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value any
	if e := d.Decode(&value); e != nil {
		return e
	}
	t := reflect.TypeOf(dst)
	if t == nil || t.Kind() != reflect.Pointer {
		return fmt.Errorf("output pointer required")
	}
	if e := shapeMode(value, t.Elem(), "", false); e != nil {
		return e
	}
	return json.Unmarshal(data, dst)
}
