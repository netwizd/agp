package configmodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

type Format string

const (
	JSON Format = "json"
	YAML Format = "yaml"
)
const MaxDepth = 32

func problem(path, code, message string) error {
	if len(path) > 512 {
		path = path[:512]
		for !utf8.ValidString(path) {
			path = path[:len(path)-1]
		}
	}
	return &ValidationError{[]Issue{{Path: path, Code: code, Message: message, Severity: "error"}}}
}
func pointer(path, key string) string {
	return path + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}
func readBounded(r io.Reader, max int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, problem("", "byte_limit", "document exceeds capacity byte budget")
	}
	if !utf8.Valid(b) {
		return nil, problem("", "invalid_utf8", "document must be valid UTF-8")
	}
	return b, nil
}

// StrictJSON is reusable for closed HTTP envelopes. Unknown/missing fields are
// checked against the exact JSON tags, including case, rather than Go's
// case-insensitive field matching. maxBytes bounds the complete envelope.
func StrictJSON(r io.Reader, out any, maxBytes int) error {
	b, err := readBounded(r, maxBytes)
	if err != nil {
		return err
	}
	v, err := jsonValue(b)
	if err != nil {
		return err
	}
	return decodeTyped(v, out)
}
func jsonValue(b []byte) (any, error) {
	if err := validEscapedUnicode(b); err != nil {
		return nil, err
	}
	if err := jsonPreflight(b); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	nodes, routes := 0, 0
	var read func(string, int) (any, error)
	read = func(path string, depth int) (any, error) {
		if depth > MaxDepth {
			return nil, problem(path, "depth_limit", "maximum document depth is 32")
		}
		nodes++
		if nodes > 4000000 {
			return nil, problem(path, "object_limit", "too many JSON values")
		}
		token, err := d.Token()
		if err != nil {
			return nil, problem(path, "invalid_json", err.Error())
		}
		switch x := token.(type) {
		case json.Delim:
			switch x {
			case '{':
				m := map[string]any{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return nil, err
					}
					key, ok := k.(string)
					if len(key) > 128 {
						return nil, problem(path, "key_limit", "object key exceeds 128 bytes")
					}
					if !ok {
						return nil, problem(path, "invalid_json", "object key must be string")
					}
					if _, ok := m[key]; ok {
						return nil, problem(pointer(path, key), "duplicate_key", "duplicate object key")
					}
					if len(m) >= 64 {
						return nil, problem(path, "object_limit", "object has too many fields")
					}
					v, err := read(pointer(path, key), depth+1)
					if err != nil {
						return nil, err
					}
					m[key] = v
				}
				if _, err := d.Token(); err != nil {
					return nil, err
				}
				return m, nil
			case '[':
				a := make([]any, 0)
				max := 20000
				switch {
				case path == "/inputs" || strings.HasSuffix(path, "/resolvedInputs"):
					max = 50000
				case path == "/gateways":
					max = 10000
				case strings.HasSuffix(path, "/routes"):
					max = 1000
				case strings.HasSuffix(path, "/nodeIds"):
					max = 500
				case path == "/members" || path == "/conflicts":
					max = 10000
				}
				for d.More() {
					if len(a) >= max {
						return nil, problem(path, "count_limit", "array exceeds maximum capacity")
					}
					if strings.HasSuffix(path, "/routes") {
						routes++
						if routes > 100000 {
							return nil, problem(path, "route_limit", "maximum total routes is 100000")
						}
					}
					v, err := read(pointer(path, strconv.Itoa(len(a))), depth+1)
					if err != nil {
						return nil, err
					}
					a = append(a, v)
				}
				if _, err := d.Token(); err != nil {
					return nil, err
				}
				return a, nil
			}
		case string:
			if len(x) > 8192 {
				return nil, problem(path, "string_limit", "string exceeds parser budget")
			}
			return x, nil
		case json.Number:
			if strings.ContainsAny(string(x), ".eE+") {
				return nil, problem(path, "invalid_number", "only exact bounded integer numbers are supported")
			}
			if n, err := strconv.ParseInt(string(x), 10, 64); err != nil || strconv.FormatInt(n, 10) != string(x) {
				return nil, problem(path, "invalid_number", "integer is out of range")
			}
			return x, nil
		case bool, nil:
			return x, nil
		}
		return nil, problem(path, "invalid_json", "unexpected JSON token")
	}
	v, err := read("", 1)
	if err != nil {
		return nil, err
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, problem("", "object_required", "one object is required")
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, problem("", "multiple_documents", "exactly one JSON object is required")
	}
	return v, nil
}
func yamlValue(b []byte) (any, error) {
	if err := yamlPreflight(b); err != nil {
		return nil, err
	}
	var root yaml.Node
	d := yaml.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&root); err != nil {
		return nil, problem("", "invalid_yaml", err.Error())
	}
	var extra yaml.Node
	if err := d.Decode(&extra); err != io.EOF {
		return nil, problem("", "multiple_documents", "exactly one YAML document is required")
	}
	nodes, routes := 0, 0
	var walk func(*yaml.Node, string, int) (any, error)
	walk = func(n *yaml.Node, path string, depth int) (any, error) {
		nodes++
		if nodes > 4000000 || depth > MaxDepth {
			return nil, problem(path, "depth_limit", "YAML document exceeds parser budget")
		}
		if n.Anchor != "" || n.Kind == yaml.AliasNode || n.Style&yaml.TaggedStyle != 0 {
			return nil, problem(path, "yaml_reference_forbidden", "anchors, aliases and explicit tags are forbidden")
		}
		switch n.Kind {
		case yaml.DocumentNode:
			if len(n.Content) != 1 {
				return nil, problem(path, "object_required", "one object is required")
			}
			return walk(n.Content[0], path, depth)
		case yaml.MappingNode:
			if len(n.Content) > 128 {
				return nil, problem(path, "object_limit", "object has too many fields")
			}
			m := map[string]any{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if len(k.Value) > 128 {
					return nil, problem(path, "key_limit", "object key exceeds 128 bytes")
				}
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || k.Anchor != "" || k.Style&yaml.TaggedStyle != 0 {
					return nil, problem(path, "invalid_yaml_key", "only plain string keys are supported; merge keys are forbidden")
				}
				if _, ok := m[k.Value]; ok {
					return nil, problem(pointer(path, k.Value), "duplicate_key", "duplicate YAML key")
				}
				v, err := walk(n.Content[i+1], pointer(path, k.Value), depth+1)
				if err != nil {
					return nil, err
				}
				m[k.Value] = v
			}
			return m, nil
		case yaml.SequenceNode:
			max := 20000
			if path == "/inputs" {
				max = 50000
			}
			if path == "/gateways" || path == "/members" || path == "/conflicts" {
				max = 10000
			}
			if strings.HasSuffix(path, "/routes") {
				max = 1000
				routes += len(n.Content)
				if routes > 100000 {
					return nil, problem(path, "route_limit", "maximum total routes is 100000")
				}
			}
			if len(n.Content) > max {
				return nil, problem(path, "count_limit", "YAML sequence exceeds capacity")
			}
			a := make([]any, 0, len(n.Content))
			for i, child := range n.Content {
				v, err := walk(child, pointer(path, strconv.Itoa(i)), depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			return a, nil
		case yaml.ScalarNode:
			if len(n.Value) > 8192 {
				return nil, problem(path, "string_limit", "scalar exceeds parser budget")
			}
			switch n.Tag {
			case "!!str", "!!timestamp":
				return n.Value, nil
			case "!!bool":
				if n.Value != "true" && n.Value != "false" {
					return nil, problem(path, "yaml_coercion", "booleans must be true or false")
				}
				return n.Value == "true", nil
			case "!!int":
				if !integerPattern.MatchString(n.Value) {
					return nil, problem(path, "yaml_coercion", "integers must use canonical decimal notation")
				}
				if _, err := strconv.ParseInt(n.Value, 10, 64); err != nil {
					return nil, problem(path, "invalid_number", "integer out of range")
				}
				return json.Number(n.Value), nil
			default:
				return nil, problem(path, "yaml_coercion", "null, floating point and implicit custom scalar types are forbidden")
			}
		}
		return nil, problem(path, "invalid_yaml", "unsupported YAML node")
	}
	v, err := walk(&root, "", 1)
	if err != nil {
		return nil, err
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, problem("", "object_required", "one object is required")
	}
	return v, nil
}

var integerPattern = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

func decodeTyped(v any, out any) error {
	t := reflect.TypeOf(out)
	if t == nil || t.Kind() != reflect.Pointer {
		return fmt.Errorf("typed output must be a pointer")
	}
	if err := shape(v, t.Elem(), ""); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
func shape(v any, t reflect.Type, path string) error { return shapeMode(v, t, path, true) }
func shapeMode(v any, t reflect.Type, path string, required bool) error {
	if reflect.PointerTo(t).Implements(reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()) {
		raw, _ := json.Marshal(v)
		target := reflect.New(t).Interface()
		if err := json.Unmarshal(raw, target); err != nil {
			return problem(path, "type_mismatch", err.Error())
		}
		return nil
	}

	if t.Kind() == reflect.Pointer {
		if v == nil {
			return problem(path, "null_forbidden", "null is not an optional field")
		}
		return shapeMode(v, t.Elem(), path, required)
	}
	if v == nil {
		return problem(path, "null_forbidden", "null is not supported")
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return problem(path, "type_mismatch", "object required")
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			fields[tag[0]] = f
			if _, exists := m[tag[0]]; !exists && required && !strings.Contains(f.Tag.Get("json"), "omitempty") {
				return problem(pointer(path, tag[0]), "required_field", "required field is missing")
			}
		}
		for k, value := range m {
			f, ok := fields[k]
			if !ok {
				return problem(pointer(path, k), "unknown_field", "unknown field")
			}
			if err := shapeMode(value, f.Type, pointer(path, k), required); err != nil {
				return err
			}
			if err := tagValidate(value, f.Tag.Get("v"), pointer(path, k)); err != nil {
				return err
			}
		}
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok {
			return problem(path, "type_mismatch", "map required")
		}
		if len(m) > 32 {
			return problem(path, "label_limit", "maximum 32 labels")
		}
		for k, value := range m {
			if !labelPattern.MatchString(k) {
				return problem(pointer(path, k), "invalid_label", "invalid label key")
			}
			str, ok := value.(string)
			if !ok || utf8.RuneCountInString(str) < 1 || utf8.RuneCountInString(str) > 128 {
				return problem(pointer(path, k), "invalid_label", "label value must be a string of 1..128 characters")
			}
		}
	case reflect.Slice:
		a, ok := v.([]any)
		if !ok {
			return problem(path, "type_mismatch", "array required")
		}
		for i, item := range a {
			if err := shapeMode(item, t.Elem(), pointer(path, strconv.Itoa(i)), required); err != nil {
				return err
			}
		}
	case reflect.String:
		if _, ok := v.(string); !ok {
			return problem(path, "type_mismatch", "string required")
		}
	case reflect.Bool:
		if _, ok := v.(bool); !ok {
			return problem(path, "type_mismatch", "boolean required")
		}
	case reflect.Int:
		if _, ok := v.(json.Number); !ok {
			return problem(path, "type_mismatch", "exact integer required")
		}
	default:
		return fmt.Errorf("unsupported closed DTO type %s", t)
	}
	return nil
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var labelPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)

func ValidID(s string) bool     { return idPattern.MatchString(s) }
func ValidDigest(s string) bool { return digestPattern.MatchString(s) }
func tagValidate(v any, tag, path string) error {
	for _, rule := range strings.Split(tag, ",") {
		parts := strings.SplitN(rule, "=", 2)
		switch parts[0] {
		case "id":
			if !ValidID(fmt.Sprint(v)) {
				return problem(path, "invalid_id", "invalid opaque ID")
			}
		case "digest":
			if !ValidDigest(fmt.Sprint(v)) {
				return problem(path, "invalid_digest", "expected sha256 digest")
			}
		case "const":
			if fmt.Sprint(v) != parts[1] {
				return problem(path, "invalid_value", "unexpected constant")
			}
		case "enum":
			if !strings.Contains("|"+parts[1]+"|", "|"+fmt.Sprint(v)+"|") {
				return problem(path, "invalid_value", "unsupported enum value")
			}
		case "min", "max":
			bound, _ := strconv.Atoi(parts[1])
			size := 0
			switch x := v.(type) {
			case string:
				size = utf8.RuneCountInString(x)
			case []any:
				size = len(x)
			case json.Number:
				n, _ := strconv.ParseInt(string(x), 10, 64)
				size = int(n)
			}
			if parts[0] == "min" && size < bound || parts[0] == "max" && size > bound {
				return problem(path, "range_limit", "value exceeds schema range")
			}
		case "ids":
			seen := map[string]bool{}
			for i, x := range v.([]any) {
				s := fmt.Sprint(x)
				if !ValidID(s) {
					return problem(pointer(path, strconv.Itoa(i)), "invalid_id", "invalid opaque ID")
				}
				if seen[s] {
					return problem(path, "duplicate_item", "set contains a duplicate ID")
				}
				seen[s] = true
			}
		case "utc":
			if err := validUTC(fmt.Sprint(v)); err != nil {
				return problem(path, "invalid_time", err.Error())
			}
		}
	}
	return nil
}
func parse(r io.Reader, format Format, max int, out any) error {
	b, err := readBounded(r, max)
	if err != nil {
		return err
	}
	var v any
	switch format {
	case JSON:
		v, err = jsonValue(b)
	case YAML:
		v, err = yamlValue(b)
	default:
		return problem("", "unsupported_format", "only json or yaml is supported")
	}
	if err != nil {
		return err
	}
	return decodeTyped(v, out)
}
func ParseConfiguration(r io.Reader, f Format) (*Document, error) {
	var c Configuration
	if err := parse(r, f, Fleet.MaxBytes, &c); err != nil {
		return nil, err
	}
	return Canonicalize(c)
}
func ParseGateway(r io.Reader, f Format) (*Gateway, error) {
	return ParseGatewayForProfile(r, f, Pilot.Profile)
}

// ParseGatewayForProfile retains the explicit capacity of the calling workflow.
// Gateways have the same closed schema in pilot and fleet configurations.
func ParseGatewayForProfile(r io.Reader, f Format, profile string) (*Gateway, error) {
	var maxBytes int
	switch profile {
	case Pilot.Profile:
		maxBytes = Pilot.MaxBytes
	case Fleet.Profile:
		maxBytes = Fleet.MaxBytes
	default:
		return nil, problem("", "unsupported_capacity_profile", "unsupported gateway capacity profile")
	}
	var g Gateway
	if err := parse(r, f, maxBytes, &g); err != nil {
		return nil, err
	}
	if err := NormalizeGateway(&g); err != nil {
		return nil, err
	}
	return &g, nil
}

// ParseRoute parses the closed route DTO without introducing gateway metadata
// or infrastructure defaults.
func ParseRoute(r io.Reader, f Format) (*Route, error) {
	var route Route
	if err := parse(r, f, Pilot.MaxBytes, &route); err != nil {
		return nil, err
	}
	if err := NormalizeRoute(&route); err != nil {
		return nil, err
	}
	return &route, nil
}
func ParseWafZone(r io.Reader, f Format) (*WafZone, error) {
	var z WafZone
	if err := parse(r, f, Pilot.MaxBytes, &z); err != nil {
		return nil, err
	}
	if err := ValidateWafZone(&z); err != nil {
		return nil, err
	}
	return &z, nil
}
func ParsePolicyProfile(r io.Reader, f Format) (*PolicyProfile, error) {
	var p PolicyProfile
	if err := parse(r, f, Pilot.MaxBytes, &p); err != nil {
		return nil, err
	}
	if err := ValidateProfile(&p); err != nil {
		return nil, err
	}
	return &p, nil
}
func ParseZoneResolution(r io.Reader, f Format) (*WafZoneResolution, error) {
	var v WafZoneResolution
	if err := parse(r, f, Fleet.MaxBytes, &v); err != nil {
		return nil, err
	}
	if err := ValidateResolution(&v); err != nil {
		return nil, err
	}
	return &v, nil
}
func ParseZoneChange(r io.Reader, f Format) (*WafZoneChange, error) {
	var v WafZoneChange
	return &v, parse(r, f, Pilot.MaxBytes, &v)
}

// ValidateJSON checks one UTF-8 JSON object, duplicate keys, Unicode escapes,
// depth and object budgets. The caller bounds the HTTP envelope byte budget;
// document strings may legitimately contain an entire fleet snapshot.
func ValidateJSON(data []byte) error {
	if !utf8.Valid(data) {
		return problem("", "invalid_utf8", "valid UTF-8 required")
	}
	if err := validEscapedUnicode(data); err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return problem("", "object_required", "one JSON object required")
	}
	return jsonPreflightWithStrings(data, len(data))
}
func DecodeJSON(data []byte, dst any) error {
	if err := ValidateJSON(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return err
	}
	return decodeTyped(v, dst)
}

// DecodeEnvelopeJSON checks exact declared fields, including nested closed DTOs,
// without inferring requiredness from non-omitempty Go fields. Endpoint-specific
// required fields are validated by the service. Document strings remain bounded
// by the caller's HTTP limit and the selected document parser, not the 8KiB
// closed-configuration scalar budget.
func DecodeEnvelopeJSON(data []byte, dst any) error {
	if err := ValidateJSON(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return err
	}
	t := reflect.TypeOf(dst)
	if t == nil || t.Kind() != reflect.Pointer {
		return fmt.Errorf("output pointer required")
	}
	if err := shapeMode(v, t.Elem(), "", false); err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

// ParseConfigurationForProfile keeps older caller capacity contracts closed.
// The generic parser supports both explicit versions without silently upgrading
// a pilot consumer to the fleet envelope.
func ParseConfigurationForProfile(r io.Reader, f Format, profile string) (*Document, error) {
	d, err := ParseConfiguration(r, f)
	if err != nil {
		return nil, err
	}
	if d.Capacity.Profile != profile {
		return nil, problem("/apiVersion", "unsupported_capacity_profile", "document requires a different explicit capacity profile")
	}
	return d, nil
}
