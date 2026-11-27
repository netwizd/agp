package configmodel

import (
	"golang.org/x/text/unicode/norm"
	"io"
	"sort"
)

// Catalog is an immutable authoring inventory. Its operator-declared entries
// are never evidence of a connected node, native validation or qualified tuple.
type Catalog struct {
	APIVersion string         `json:"apiVersion" v:"const=agp.catalog/v1alpha1"`
	ID         string         `json:"id" v:"id"`
	SourceKind string         `json:"sourceKind" v:"const=operator_declared"`
	SourceRef  string         `json:"sourceRef" v:"min=1,max=512"`
	RecordedAt string         `json:"recordedAt" v:"utc"`
	Sites      []CatalogSite  `json:"sites" v:"max=10000"`
	Nodes      []CatalogNode  `json:"nodes" v:"max=500"`
	Groups     []string       `json:"groups" v:"max=20000,ids"`
	Inputs     []CatalogInput `json:"inputs" v:"max=50000"`
}
type CatalogSite struct {
	ID string `json:"id" v:"id"`
}
type CatalogNode struct {
	ID                   string   `json:"id" v:"id"`
	SiteID               string   `json:"siteId" v:"id"`
	Labels               Labels   `json:"labels"`
	NodeGroupIDs         []string `json:"nodeGroupIds" v:"max=500,ids"`
	CapabilityDigest     string   `json:"capabilityDigest,omitempty" v:"digest"`
	BaselineBundleDigest string   `json:"baselineBundleDigest,omitempty" v:"digest"`
}
type CatalogInput struct {
	Kind               string         `json:"kind" v:"enum=access_policy|waf_policy|ruleset|component_profile|certificate|policy_profile|assignment_resolution"`
	ID                 string         `json:"id" v:"id"`
	Digest             string         `json:"digest" v:"digest"`
	SiteID             string         `json:"siteId,omitempty" v:"id"`
	State              string         `json:"state" v:"const=published"`
	Profile            *PolicyProfile `json:"profile,omitempty"`
	BaseExceptionCount int            `json:"baseExceptionCount" v:"min=0,max=100"`
}
type CatalogDocument struct {
	Catalog   Catalog
	Canonical []byte
	Digest    string
}

func ParseCatalog(r io.Reader, f Format) (*CatalogDocument, error) {
	var c Catalog
	if err := parse(r, f, Fleet.MaxBytes, &c); err != nil {
		return nil, err
	}
	return CanonicalizeCatalog(c)
}
func CanonicalizeCatalog(c Catalog) (*CatalogDocument, error) {
	c.SourceRef = norm.NFC.String(c.SourceRef)
	raw, err := CanonicalJSON(c)
	if err != nil {
		return nil, err
	}
	v, err := jsonValue(raw)
	if err != nil {
		return nil, err
	}
	if err = decodeTyped(v, &c); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	sites := map[string]bool{}
	for _, s := range c.Sites {
		if seen[s.ID] {
			return nil, problem("/sites", "duplicate_id", "duplicate catalog ID")
		}
		seen[s.ID] = true
		sites[s.ID] = true
	}
	for i := range c.Nodes {
		n := &c.Nodes[i]
		normalizeLabels(n.Labels)
		if seen[n.ID] || !sites[n.SiteID] {
			return nil, problem("/nodes", "invalid_reference", "duplicate node ID or unknown Site")
		}
		seen[n.ID] = true
		set(n.NodeGroupIDs)
	}
	for _, id := range c.Groups {
		if seen[id] {
			return nil, problem("/groups", "duplicate_id", "duplicate catalog ID")
		}
		seen[id] = true
	}
	for i := range c.Inputs {
		p := &c.Inputs[i]
		if seen[p.ID] {
			return nil, problem("/inputs", "duplicate_id", "duplicate catalog ID")
		}
		seen[p.ID] = true
		if p.Kind == "waf_policy" && p.SiteID == "" {
			return nil, problem("/inputs", "site_required", "WAF policy input requires a Site")
		}
		if p.SiteID != "" && !sites[p.SiteID] {
			return nil, problem("/inputs", "invalid_reference", "unknown input Site")
		}
		if p.Kind == "policy_profile" {
			if p.Profile == nil {
				return nil, problem("/inputs", "profile_required", "policy profile content is required")
			}
			if err := ValidateProfile(p.Profile); err != nil {
				return nil, err
			}
			if p.SiteID != p.Profile.Metadata.SiteID {
				return nil, problem("/inputs", "profile_scope_mismatch", "profile content Site differs from input scope")
			}
			digest, err := Digest(p.Profile)
			if err != nil || digest != p.Digest {
				return nil, problem("/inputs", "digest_mismatch", "policy profile content differs from its pinned digest")
			}

		} else if p.Profile != nil {
			return nil, problem("/inputs", "unexpected_profile", "profile content is only valid for policy_profile")
		}
	}
	sort.Slice(c.Sites, func(i, j int) bool { return c.Sites[i].ID < c.Sites[j].ID })
	sort.Slice(c.Nodes, func(i, j int) bool { return c.Nodes[i].ID < c.Nodes[j].ID })
	set(c.Groups)
	sort.Slice(c.Inputs, func(i, j int) bool {
		if c.Inputs[i].Kind != c.Inputs[j].Kind {
			return c.Inputs[i].Kind < c.Inputs[j].Kind
		}
		return c.Inputs[i].ID < c.Inputs[j].ID
	})
	canonical, err := CanonicalJSON(c)
	if err != nil {
		return nil, err
	}
	if len(canonical) > Fleet.MaxBytes {
		return nil, problem("", "byte_limit", "catalog exceeds byte budget")
	}
	return &CatalogDocument{Catalog: c, Canonical: canonical, Digest: DigestBytes(canonical)}, nil
}
