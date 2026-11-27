package configmodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func validEscapedUnicode(b []byte) error {
	quoted := false
	hex4 := func(p int) (uint64, error) {
		if p+4 > len(b) {
			return 0, fmt.Errorf("short Unicode escape")
		}
		return strconv.ParseUint(string(b[p:p+4]), 16, 16)
	}
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return problem("", "invalid_json", "trailing escape")
		}
		if b[i] != 'u' {
			continue
		}
		n, err := hex4(i + 1)
		if err != nil {
			return problem("", "invalid_unicode", "invalid Unicode escape")
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return problem("", "invalid_unicode", "unpaired Unicode high surrogate")
			}
			low, err := hex4(i + 3)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return problem("", "invalid_unicode", "invalid Unicode surrogate pair")
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return problem("", "invalid_unicode", "unpaired Unicode low surrogate")
		}
	}
	return nil
}

// jsonPreflight validates depth and cumulative cardinality before allocating
// model maps/slices. Scalar tokens are transient; each key set is capped at 64.
func jsonPreflight(b []byte) error { return jsonPreflightWithStrings(b, 8192) }
func jsonPreflightWithStrings(b []byte, maxString int) error {
	return jsonPreflightWithArrayLimits(b, maxString, nil)
}

func jsonPreflightWithArrayLimits(b []byte, maxString int, arrayLimits map[string]int) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	nodes, routes, gateways, assignments := 0, 0, 0, 0
	version, profile, kind := "", "", ""
	var read func(string, int) error
	read = func(path string, depth int) error {
		if depth > MaxDepth {
			return problem(path, "depth_limit", "maximum document depth is 32")
		}
		nodes++
		if nodes > 4000000 {
			return problem(path, "object_limit", "too many values")
		}
		t, err := d.Token()
		if err != nil {
			return problem(path, "invalid_json", err.Error())
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					token, err := d.Token()
					if err != nil {
						return err
					}
					key, ok := token.(string)
					if !ok || len(key) > 128 {
						return problem(path, "key_limit", "invalid or oversized object key")
					}
					if seen[key] {
						return problem(pointer(path, key), "duplicate_key", "duplicate object key")
					}
					if len(seen) >= 64 {
						return problem(path, "object_limit", "too many object fields")
					}
					seen[key] = true
					if err = read(pointer(path, key), depth+1); err != nil {
						return err
					}
				}
				_, err = d.Token()
				return err
			case '[':
				count := 0
				max := 20000
				if path == "/inputs" || strings.HasSuffix(path, "/resolvedInputs") {
					max = 50000
				}
				if limit, ok := arrayLimits[path]; ok {
					max = limit
				}
				for d.More() {
					count++
					if count > max {
						return problem(path, "count_limit", "too many array members")
					}
					if path == "/gateways" {
						gateways++
						if gateways > 10000 {
							return problem(path, "count_limit", "too many Gateways")
						}
					}
					if path == "/profileAssignments" {
						assignments++
						if assignments > 20000 {
							return problem(path, "count_limit", "too many assignments")
						}
					}
					if strings.HasSuffix(path, "/routes") {
						routes++
						if count > 1000 || routes > 100000 {
							return problem(path, "route_limit", "route budget exceeded")
						}
					}
					if err = read(pointer(path, strconv.Itoa(count-1)), depth+1); err != nil {
						return err
					}
				}
				_, err = d.Token()
				return err
			}
			return problem(path, "invalid_json", "unexpected delimiter")
		}
		if s, ok := t.(string); ok {
			if len(s) > maxString {
				return problem(path, "string_limit", "scalar exceeds parser budget")
			}
			if path == "/apiVersion" {
				version = s
			}
			if path == "/capacityProfile" {
				profile = s
			}
			if path == "/kind" {
				kind = s
			}
		}
		return nil
	}
	if err := read("", 1); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return problem("", "multiple_documents", "one JSON object required")
	}
	if version == "agp.config/v1alpha1" {
		// Gateway shares this apiVersion with Configuration. Its explicit
		// caller-selected byte limit is enforced before this preflight; it
		// does not implicitly select the pilot Configuration envelope.
		if kind != "Gateway" && (len(b) > Pilot.MaxBytes || gateways > Pilot.MaxGateways || assignments > Pilot.MaxAssignments) {
			return problem("", "capacity_limit", "input exceeds pilot-500 capacity")
		}
		if profile != "" {
			return problem("/capacityProfile", "unknown_field", "pilot has no capacityProfile")
		}
	}
	if version == "agp.config/v1alpha2" && profile != "fleet-10k" {
		return problem("/capacityProfile", "capacity_profile_required", "fleet profile must be explicit")
	}
	return nil
}

// yamlPreflight scans lexical nesting before yaml.v3 allocates its AST. It does
// not resolve tags/scalars; the AST pass independently enforces the closed
// JSON-compatible grammar. Quoted and block-scalar text never counts as syntax.
func yamlPreflight(b []byte) error {
	flowDepth := 0
	flowDelimiters := []byte{}
	flowCounts := []int{}
	flowLimits := []int{}
	indents := []int{}
	tokens := 0
	blockIndent := -1
	blockBytes := 0
	single, double := false, false
	sequenceCounts := map[int]int{}
	sequenceKeys := map[int]string{}
	version, profile, kind := "", "", ""
	gateways := 0
	for offset := 0; offset < len(b); {
		end := bytes.IndexByte(b[offset:], '\n')
		if end < 0 {
			end = len(b) - offset
		}
		line := b[offset : offset+end]
		offset += end + 1
		trim := bytes.TrimLeft(line, " ")
		indent := len(line) - len(trim)
		if len(trim) == 0 || trim[0] == '#' {
			continue
		}
		if blockIndent >= 0 {
			if indent > blockIndent {
				blockBytes += len(trim) + 1
				if blockBytes > 8192 {
					return problem("", "string_limit", "YAML block scalar exceeds budget before AST decoding")
				}
				continue
			}
			blockIndent = -1
		}
		if len(trim) > 8192 {
			return problem("", "yaml_line_limit", "YAML physical lines are limited to 8192 bytes; JSON supports larger flow documents")
		}
		if flowDepth == 0 {
			text := strings.TrimSpace(string(trim))
			if indent == 0 && strings.HasPrefix(text, "apiVersion:") {
				version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(text, "apiVersion:")), "\"'")
			}
			if indent == 0 && strings.HasPrefix(text, "capacityProfile:") {
				profile = strings.Trim(strings.TrimSpace(strings.TrimPrefix(text, "capacityProfile:")), "\"'")
			}
			if indent == 0 && strings.HasPrefix(text, "kind:") {
				kind = strings.Trim(strings.TrimSpace(strings.TrimPrefix(text, "kind:")), "\"'")
			}
			for level := range sequenceCounts {
				if level > indent {
					delete(sequenceCounts, level)
					delete(sequenceKeys, level)
				}
			}
			if strings.HasPrefix(text, "- ") || text == "-" {
				sequenceCounts[indent]++
				max := 20000
				key := sequenceKeys[indent]
				if key == "inputs" {
					max = 50000
				}
				if key == "gateways" {
					max = 10000
					gateways++
				}
				if key == "routes" {
					max = 1000
				}
				if key == "nodeIds" {
					max = 500
				}
				if sequenceCounts[indent] > max {
					return problem("", "count_limit", "YAML sequence exceeds capacity before AST decoding")
				}
			} else if strings.HasSuffix(text, ":") {
				key := strings.Trim(strings.TrimSuffix(text, ":"), "\"'")
				sequenceKeys[indent] = key
				sequenceKeys[indent+2] = key
				sequenceCounts[indent] = 0
				sequenceCounts[indent+2] = 0
			}
		}
		if !single && !double && flowDepth == 0 {
			for len(indents) > 0 && indent < indents[len(indents)-1] {
				indents = indents[:len(indents)-1]
			}
			if len(indents) == 0 || indent > indents[len(indents)-1] {
				indents = append(indents, indent)
			}
			if len(indents) > MaxDepth {
				return problem("", "depth_limit", "YAML indentation exceeds maximum depth")
			}
		}
		for i := 0; i < len(trim); i++ {
			c := trim[i]
			if double {
				if c == '\\' {
					i++
					continue
				}
				if c == '"' {
					double = false
				}
				continue
			}
			if single {
				if c == '\'' {
					if i+1 < len(trim) && trim[i+1] == '\'' {
						i++
						continue
					}
					single = false
				}
				continue
			}
			if c == '#' && (i == 0 || trim[i-1] == ' ') {
				break
			}
			if c == '"' {
				j := i - 1
				for j >= 0 && trim[j] == ' ' {
					j--
				}
				if j >= 0 && !strings.ContainsRune(":,[{-", rune(trim[j])) {
					return problem("", "yaml_ambiguous_scalar", "quotes inside a plain scalar must be quoted or escaped as a complete scalar")
				}
				double = true
				continue
			}
			if c == '\'' {
				j := i - 1
				for j >= 0 && trim[j] == ' ' {
					j--
				}
				if j >= 0 && !strings.ContainsRune(":,[{-", rune(trim[j])) {
					return problem("", "yaml_ambiguous_scalar", "quotes inside a plain scalar must be quoted as a complete scalar")
				}
				single = true
				continue
			}
			if c == '[' || c == '{' {
				flowDelimiters = append(flowDelimiters, c)
				flowCounts = append(flowCounts, 1)
				limit := 20000
				if c == '[' {
					prefix := strings.TrimSpace(string(trim[:i]))
					if colon := strings.LastIndexByte(prefix, ':'); colon >= 0 {
						key := strings.Trim(strings.TrimSpace(prefix[:colon]), "{\"' ")
						if key == "inputs" {
							limit = 50000
						}
					}
				}
				flowLimits = append(flowLimits, limit)
				flowDepth++
				tokens++
				if flowDepth+len(indents) > MaxDepth {
					return problem("", "depth_limit", "YAML flow nesting exceeds maximum depth")
				}
			}
			if c == ',' && len(flowDelimiters) > 0 && flowDelimiters[len(flowDelimiters)-1] == '[' {
				index := len(flowCounts) - 1
				flowCounts[index]++
				if flowCounts[index] > flowLimits[index] {
					return problem("", "count_limit", "YAML flow sequence exceeds budget before AST decoding")
				}
			}
			if c == ']' || c == '}' {
				if flowDepth <= 0 {
					return problem("", "yaml_ambiguous_scalar", "unquoted flow delimiters inside plain scalar are unsupported")
				}
				flowDepth--
				flowDelimiters = flowDelimiters[:len(flowDelimiters)-1]
				flowCounts = flowCounts[:len(flowCounts)-1]
				flowLimits = flowLimits[:len(flowLimits)-1]
			}
			if c == ':' || c == ',' || c == '-' && (i == 0 || trim[i-1] == ' ') {
				tokens++
			}
			if (c == '|' || c == '>') && i > 0 && trim[i-1] == ' ' && flowDepth == 0 {
				blockIndent = indent
				blockBytes = 0
				break
			}
			if tokens > 4000000 {
				return problem("", "object_limit", "YAML exceeds object budget")
			}
		}
		if single || double {
			return problem("", "yaml_multiline_scalar", "multiline quoted scalars are unsupported; use a block scalar")
		}
	}
	if version == "agp.config/v1alpha1" && kind != "Gateway" && (len(b) > Pilot.MaxBytes || gateways > Pilot.MaxGateways) {
		return problem("", "capacity_limit", "YAML input exceeds pilot-500 before AST decoding")
	}
	if version == "agp.config/v1alpha2" && profile != "fleet-10k" {
		return problem("/capacityProfile", "capacity_profile_required", "fleet profile must be explicit")
	}
	return nil
}
