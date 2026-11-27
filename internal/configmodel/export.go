package configmodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go.yaml.in/yaml/v3"
	"sort"
)

// YAMLDocument emits JSON field names and explicit scalar types. All strings
// are quoted, so timestamps, false, leading zeroes and anchors remain strings.
func YAMLDocument(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value any
	if err = d.Decode(&value); err != nil {
		return nil, err
	}
	var node func(any) (*yaml.Node, error)
	node = func(v any) (*yaml.Node, error) {
		n := &yaml.Node{}
		switch x := v.(type) {
		case map[string]any:
			n.Kind = yaml.MappingNode
			n.Tag = "!!map"
			keys := []string{}
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				child, err := node(x[k])
				if err != nil {
					return nil, err
				}
				n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, child)
			}
		case []any:
			n.Kind = yaml.SequenceNode
			n.Tag = "!!seq"
			for _, v := range x {
				child, err := node(v)
				if err != nil {
					return nil, err
				}
				n.Content = append(n.Content, child)
			}
		case string:
			n.Kind = yaml.ScalarNode
			n.Tag = "!!str"
			n.Style = yaml.DoubleQuotedStyle
			n.Value = x
		case bool:
			n.Kind = yaml.ScalarNode
			n.Tag = "!!bool"
			if x {
				n.Value = "true"
			} else {
				n.Value = "false"
			}
		case json.Number:
			n.Kind = yaml.ScalarNode
			n.Tag = "!!int"
			n.Value = string(x)
		default:
			return nil, fmt.Errorf("null or unsupported YAML document value")
		}
		return n, nil
	}
	root, err := node(value)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	e := yaml.NewEncoder(&out)
	e.SetIndent(2)
	if err = e.Encode(root); err != nil {
		return nil, err
	}
	if err = e.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
