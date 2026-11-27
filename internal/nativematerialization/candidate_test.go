package nativematerialization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/executionsources"
	"github.com/netwizd/agp/internal/nativeactivation"
)

func candidateFixture(t *testing.T) (configmodel.Configuration, []PolicyRevision, Options) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/v2/examples/configuration.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := configmodel.ParseConfiguration(bytes.NewReader(raw), configmodel.JSON)
	if err != nil {
		t.Fatal(err)
	}
	c := doc.Configuration
	g := &c.Gateways[0]
	g.Spec.Ownership = "managed"
	g.Spec.WAF.Mode = "blocking"
	g.Spec.Routes[0].Upstream.URL = "http://127.0.0.1:18081"
	g.Spec.Routes[0].Upstream.TLS.ServerName = ""
	policy := configmodel.WafPolicy{APIVersion: "agp.waf/v1alpha1", Kind: "WafPolicy", Metadata: configmodel.WafPolicyMetadata{ID: "policy_one", Name: "Base policy", SiteID: g.Metadata.SiteID}, Spec: configmodel.WafPolicySpec{Engine: "modsecurity", RulesetVersionID: "crs_4_30_0", ParanoiaLevel: 1, InboundAnomalyThreshold: 5, OutboundAnomalyThreshold: 4, Exceptions: []configmodel.WafException{}}}
	digest, err := configmodel.Digest(policy)
	if err != nil {
		t.Fatal(err)
	}
	policies := []PolicyRevision{{RevisionID: g.Spec.WAF.PolicyRevisionID, ContentDigest: digest, Policy: policy}}
	opts := Options{BuildDigest: "sha256:" + strings.Repeat("b", 64), NodeID: g.Spec.NodeSelector.NodeIDs[0], SiteID: g.Metadata.SiteID, RevisionID: "revision_one", GenerationID: "generation_one", GenerationRoot: "/srv/agp/generation", RuntimeRoot: "/opt/agp/runtime", RunDir: "/run/agp/candidate", StateDir: "/var/lib/agp/edge", SecretDir: "/etc/agp/secrets", LoginOrigin: "https://login.example.net", CentralOrigin: "https://central.example.net", ClientCertificateFile: "/etc/agp/identity/client.pem", ClientKeyFile: "/etc/agp/identity/client.key", ServerCAFile: "/etc/agp/identity/ca.pem", ListenAddress: "0.0.0.0:443", ComponentProfileRef: g.Spec.ComponentProfileRef, RulesetVersionID: "crs_4_30_0"}
	return c, policies, opts
}

func TestCandidateDeterministicAndNeverQualified(t *testing.T) {
	c, policies, opts := candidateFixture(t)
	before, _ := json.Marshal(c)
	a, err := Compile(context.Background(), c, policies, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(context.Background(), c, policies, opts)
	if err != nil {
		t.Fatal(err)
	}
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if !bytes.Equal(aj, bj) {
		t.Fatal("candidate is not deterministic")
	}
	after, _ := json.Marshal(c)
	if !bytes.Equal(before, after) {
		t.Fatal("caller configuration mutated")
	}
	if a.Deployable || a.APIVersion == nativeactivation.BundleVersion || a.Purpose != "unsigned_service_configuration_candidate" || len(a.Blockers) == 0 {
		t.Fatal("candidate claims execution or qualification")
	}
	if !configmodel.ValidDigest(a.CandidateDigest) || a.ConfigurationDigest == "" || len(a.Gateways) != 1 || len(a.Artifacts) != 3 {
		t.Fatal("incomplete candidate")
	}
	check := *a
	check.CandidateDigest = ""
	want, _ := configmodel.Digest(check)
	if want != a.CandidateDigest {
		t.Fatal("candidate digest does not bind the complete candidate")
	}
	for _, artifact := range a.Artifacts {
		if artifact.Digest != configmodel.DigestBytes([]byte(artifact.Content)) {
			t.Fatal("artifact digest mismatch")
		}
		if artifact.Path == "nginx.conf" {
			for _, fragment := range []string{"auth_request /_agp/authorize;", "modsecurity on;", "modsecurity_rules_file /srv/agp/generation/waf/", "ssl_reject_handshake on;", "proxy_set_header X-AGP-Start \"\";"} {
				if !strings.Contains(artifact.Content, fragment) {
					t.Fatalf("missing native boundary %q", fragment)
				}
			}
		}
	}
	if a.Gateways[0].Routes[0].Access.GroupIDs[0] != c.Gateways[0].Spec.Routes[0].Access.GroupIDs[0] || a.Gateways[0].Routes[0].Upstream.ConnectTimeoutSeconds != c.Gateways[0].Spec.Routes[0].Upstream.ConnectTimeoutSeconds {
		t.Fatal("declarative access/transport policy was lost")
	}
	if a.Gateways[0].Edge.Validate() != nil {
		t.Fatal("invalid executable EdgeAuth config")
	}
	if err := configmodel.StrictJSON(bytes.NewReader(aj), &nativeactivation.Bundle{}, 1<<20); err == nil {
		t.Fatal("candidate accepted as a native bundle")
	}
	if _, err := executionsources.DecodeMaterials(append(append([]byte("["), aj...), ']')); err == nil {
		t.Fatal("candidate accepted as a trusted execution material")
	}
	// Returned artifacts/route DTOs must not alias caller-owned configuration.
	a.Gateways[0].Routes[0].Access.GroupIDs[0] = "changed_group"
	if c.Gateways[0].Spec.Routes[0].Access.GroupIDs[0] == "changed_group" {
		t.Fatal("returned candidate aliases input")
	}
}

func TestCandidatePinsEveryExecutableInput(t *testing.T) {
	for _, changed := range []string{"policy", "upstream", "groups", "tls_version", "generation", "layout", "compiler", "profile", "listen", "central"} {
		t.Run(changed, func(t *testing.T) {
			c, p, o := candidateFixture(t)
			base, err := Compile(context.Background(), c, p, o)
			if err != nil {
				t.Fatal(err)
			}
			switch changed {
			case "policy":
				p[0].Policy.Spec.ParanoiaLevel = 2
				p[0].ContentDigest, _ = configmodel.Digest(p[0].Policy)
			case "upstream":
				c.Gateways[0].Spec.Routes[0].Upstream.URL = "http://127.0.0.1:18082"
			case "groups":
				c.Gateways[0].Spec.Routes[0].Access.GroupIDs = []string{"group_other"}
			case "tls_version":
				c.Gateways[0].Spec.TLS.CertificateVersionID = "certificate_other"
			case "generation":
				o.GenerationID = "generation_two"
			case "layout":
				o.GenerationRoot = "/srv/agp/other"
			case "compiler":
				o.BuildDigest = "sha256:" + strings.Repeat("c", 64)
			case "profile":
				o.ComponentProfileRef.Digest = "sha256:" + strings.Repeat("d", 64)
				c.Gateways[0].Spec.ComponentProfileRef = o.ComponentProfileRef
			case "listen":
				o.ListenAddress = "127.0.0.1:18443"
			case "central":
				o.CentralOrigin = "https://another-central.example.net"
			}
			got, err := Compile(context.Background(), c, p, o)
			if err != nil {
				t.Fatal(err)
			}
			if got.CandidateDigest == base.CandidateDigest {
				t.Fatal("executable input did not change candidate identity")
			}
		})
	}
}

func TestCandidateRejectsUnsupportedOrAmbiguousInputs(t *testing.T) {
	for _, bad := range []string{"policy_digest", "duplicate_policy", "missing_policy", "policy_site", "ruleset", "exception", "route_exception", "profile_assignment", "label_selector", "ownership", "waf_off", "profile_mismatch", "no_recipient", "path_rewrite", "reserved_host", "path_injection", "socket_length", "listen_injection", "nil_required_field", "shared_host", "multi_host"} {
		t.Run(bad, func(t *testing.T) {
			c, p, o := candidateFixture(t)
			switch bad {
			case "policy_digest":
				p[0].Policy.Spec.ParanoiaLevel = 2
			case "duplicate_policy":
				p = append(p, p[0])
			case "missing_policy":
				p = nil
			case "policy_site":
				p[0].Policy.Metadata.SiteID = "other_site"
				p[0].ContentDigest, _ = configmodel.Digest(p[0].Policy)
			case "ruleset":
				p[0].Policy.Spec.RulesetVersionID = "other_ruleset"
				p[0].ContentDigest, _ = configmodel.Digest(p[0].Policy)
			case "exception":
				p[0].Policy.Spec.Exceptions = []configmodel.WafException{{ID: "exception_one"}}
				p[0].ContentDigest, _ = configmodel.Digest(p[0].Policy)
			case "route_exception":
				c.Gateways[0].Spec.Routes[0].WAFExceptionIDs = []string{"exception_one"}
			case "profile_assignment":
				c.ProfileAssignments = []configmodel.ProfileAssignment{{ID: "assignment_one", ProfileRevisionID: "profile_revision", ScopeType: "global"}}
			case "label_selector":
				c.Gateways[0].Spec.NodeSelector = configmodel.NodeSelector{MatchLabels: &configmodel.Labels{"role": "gateway"}}
			case "ownership":
				c.Gateways[0].Spec.Ownership = "adopted"
			case "waf_off":
				c.Gateways[0].Spec.WAF.Mode = "off"
			case "profile_mismatch":
				o.ComponentProfileRef.Digest = "sha256:" + strings.Repeat("d", 64)
			case "no_recipient":
				o.NodeID = "node_other"
			case "path_rewrite":
				c.Gateways[0].Spec.Routes[0].Upstream.URL = "http://backend.example.net/base"
			case "reserved_host":
				c.Gateways[0].Spec.Routes[0].Hostname = "login.example.net"
			case "path_injection":
				o.RuntimeRoot = "/opt/runtime;return 200;"
			case "socket_length":
				o.RunDir = "/run/" + strings.Repeat("a", 80)
			case "listen_injection":
				o.ListenAddress = "0.0.0.0:443;return200;"
			case "nil_required_field":
				c.Gateways[0].Spec.Routes[0].Access.GroupIDs = nil
			case "shared_host":
				g := c.Gateways[0]
				g.Metadata.ID = "gateway_other"
				g.Spec.Routes = append([]configmodel.Route(nil), g.Spec.Routes...)
				g.Spec.Routes[0].ID = "route_other"
				g.Spec.Routes[0].Path = "/other"
				c.Gateways = append(c.Gateways, g)
			case "multi_host":
				r := c.Gateways[0].Spec.Routes[0]
				r.ID = "route_other"
				r.Hostname = "other.example.net"
				c.Gateways[0].Spec.Routes = append(c.Gateways[0].Spec.Routes, r)
			}
			if got, err := Compile(context.Background(), c, p, o); err == nil || got != nil {
				t.Fatalf("unsupported candidate accepted: %+v", got)
			}
		})
	}
}

func TestCandidateCancellationAndCapacity(t *testing.T) {
	c, p, o := candidateFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := Compile(ctx, c, p, o); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("cancelled compilation did work")
	}
	p = make([]PolicyRevision, MaxGateways+1)
	if got, err := Compile(context.Background(), c, p, o); err == nil || got != nil {
		t.Fatal("policy capacity ignored")
	}
}
