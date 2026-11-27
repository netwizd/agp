package configmodel

import (
	"io"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// WafPolicy is the closed immutable policy contract. Assignment mode belongs to
// Gateway.spec.waf; it is deliberately absent from this document.
type WafPolicy struct {
	APIVersion string            `json:"apiVersion" v:"const=agp.waf/v1alpha1"`
	Kind       string            `json:"kind" v:"const=WafPolicy"`
	Metadata   WafPolicyMetadata `json:"metadata"`
	Spec       WafPolicySpec     `json:"spec"`
}
type WafPolicyMetadata struct {
	ID     string `json:"id" v:"id"`
	Name   string `json:"name" v:"min=1,max=128"`
	SiteID string `json:"siteId" v:"id"`
}
type WafPolicySpec struct {
	Engine                   string         `json:"engine" v:"const=modsecurity"`
	RulesetVersionID         string         `json:"rulesetVersionId" v:"id"`
	ParanoiaLevel            int            `json:"paranoiaLevel" v:"min=1,max=4"`
	InboundAnomalyThreshold  int            `json:"inboundAnomalyThreshold" v:"min=1,max=100"`
	OutboundAnomalyThreshold int            `json:"outboundAnomalyThreshold" v:"min=1,max=100"`
	Exceptions               []WafException `json:"exceptions" v:"max=100"`
}
type WafException struct {
	ID        string            `json:"id" v:"id"`
	RouteID   string            `json:"routeId" v:"id"`
	RuleIDs   []string          `json:"ruleIds" v:"min=1,max=50"`
	Match     WafExceptionMatch `json:"match"`
	OwnerID   string            `json:"ownerId" v:"id"`
	Reason    string            `json:"reason" v:"min=8,max=1024"`
	ReviewAt  string            `json:"reviewAt" v:"utc"`
	ExpiresAt string            `json:"expiresAt" v:"utc"`
}
type WafExceptionMatch struct {
	Field string `json:"field" v:"enum=query_arg|header|cookie|body_field"`
	Name  string `json:"name" v:"min=1,max=128"`
}

var wafRuleIDPattern = regexp.MustCompile(`^[0-9]{6,9}$`)
var wafMatchNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ParseWafPolicy checks the complete schema, including exceptions, without
// dropping unsupported content. The authoring service separately decides which
// policy features its qualified engine can currently support.
func ParseWafPolicy(r io.Reader, f Format) (*WafPolicy, error) {
	var p WafPolicy
	if err := parse(r, f, 2<<20, &p); err != nil {
		return nil, err
	}
	p.Metadata.Name = norm.NFC.String(p.Metadata.Name)
	if utf8.RuneCountInString(p.Metadata.Name) > 128 {
		return nil, problem("/metadata/name", "range_limit", "name exceeds schema range")
	}
	seen := map[string]bool{}
	for i := range p.Spec.Exceptions {
		e := &p.Spec.Exceptions[i]
		if seen[e.ID] {
			return nil, problem("/spec/exceptions", "duplicate_id", "duplicate exception ID")
		}
		seen[e.ID] = true
		if !wafMatchNamePattern.MatchString(e.Match.Name) {
			return nil, problem("/spec/exceptions", "invalid_match_name", "invalid exception match name")
		}
		rules := map[string]bool{}
		for _, id := range e.RuleIDs {
			if !wafRuleIDPattern.MatchString(id) || rules[id] {
				return nil, problem("/spec/exceptions", "invalid_rule_id", "rule IDs must be unique decimal strings of 6..9 digits")
			}
			rules[id] = true
		}
		sort.Strings(e.RuleIDs)
		e.Reason = norm.NFC.String(e.Reason)
		if n := utf8.RuneCountInString(e.Reason); n < 8 || n > 1024 {
			return nil, problem("/spec/exceptions", "range_limit", "normalized reason exceeds schema range")
		}
		review, _ := time.Parse(time.RFC3339Nano, e.ReviewAt)
		expires, _ := time.Parse(time.RFC3339Nano, e.ExpiresAt)
		if !review.Before(expires) {
			return nil, problem("/spec/exceptions", "invalid_exception_lifetime", "review must precede exception expiry")
		}
	}
	sort.Slice(p.Spec.Exceptions, func(i, j int) bool { return p.Spec.Exceptions[i].ID < p.Spec.Exceptions[j].ID })
	return &p, nil
}
