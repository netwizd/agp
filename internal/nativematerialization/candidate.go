// Package nativematerialization compiles unsigned service configuration candidates.
// Candidates are inspection inputs for an independent qualifier, never native
// activation bundles, execution permission, or evidence that a service works.
package nativematerialization

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/edgeauth"
	nginx "github.com/netwizd/agp/internal/reverseproxy/nginx"
	"github.com/netwizd/agp/internal/wafnative"
)

const (
	CandidateVersion = "agp.unsigned-service-candidate/v1alpha1"
	CompilerVersion  = "agp.service-candidate-compiler/v1"
	MaxArtifactBytes = 16 << 20
	MaxGateways      = 100
	MaxRoutes        = 1000
)

// PolicyRevision pins content; it does not assert publication or qualification.
type PolicyRevision struct {
	RevisionID    string                `json:"revisionId"`
	ContentDigest string                `json:"contentDigest"`
	Policy        configmodel.WafPolicy `json:"policy"`
}

// Options describes a proposed installation layout. No paths are opened by
// Compile; trust, ownership, mount identity, secrets and runtime closure must
// subsequently be checked by the independent qualifier and installer.
type Options struct {
	BuildDigest, NodeID, SiteID, RevisionID, GenerationID    string
	GenerationRoot, RuntimeRoot, RunDir, StateDir, SecretDir string
	LoginOrigin, CentralOrigin                               string
	ClientCertificateFile, ClientKeyFile, ServerCAFile       string
	ListenAddress                                            string
	RulesetVersionID                                         string
	ComponentProfileRef                                      configmodel.Reference
}

type Artifact struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Digest  string `json:"digest"`
}

// Gateway records the full declarative routes beside the executable EdgeAuth
// projection. Unsupported transport knobs are retained and explicitly blocked,
// never silently claimed to be enforced by the current EdgeAuth transport.
type Gateway struct {
	GatewayID           string              `json:"gatewayId"`
	Hostname            string              `json:"hostname"`
	Edge                edgeauth.Config     `json:"edge"`
	Routes              []configmodel.Route `json:"routes"`
	WAFPolicyRevisionID string              `json:"wafPolicyRevisionId"`
	WAFPolicyDigest     string              `json:"wafPolicyDigest"`
}

// Candidate intentionally has neither nativeactivation.Bundle's apiVersion nor
// its BundleDigest, probes, qualification digest or signature. Deployable is
// always false; callers cannot promote this result by toggling a compiler flag.
type Candidate struct {
	APIVersion          string                `json:"apiVersion"`
	Purpose             string                `json:"purpose"`
	Deployable          bool                  `json:"deployable"`
	CompilerVersion     string                `json:"compilerVersion"`
	CompilerDigest      string                `json:"compilerDigest"`
	ConfigurationDigest string                `json:"configurationDigest"`
	NodeID              string                `json:"nodeId"`
	SiteID              string                `json:"siteId"`
	RevisionID          string                `json:"revisionId"`
	GenerationID        string                `json:"generationId"`
	ComponentProfileRef configmodel.Reference `json:"componentProfileRef"`
	RulesetVersionID    string                `json:"rulesetVersionId"`
	Gateways            []Gateway             `json:"gateways"`
	SecretVersionIDs    []string              `json:"secretVersionIds"`
	Artifacts           []Artifact            `json:"artifacts"`
	Blockers            []string              `json:"blockers"`
	CandidateDigest     string                `json:"candidateDigest"`
}

var simpleAbsolutePath = regexp.MustCompile(`^/[A-Za-z0-9/_.+-]+$`)

func validAbsolutePath(p string) bool {
	return len(p) <= 4096 && p != "/" && simpleAbsolutePath.MatchString(p) && path.Clean(p) == p
}

// Compile is deterministic and performs no filesystem, network or native process
// work. It supports managed Gateways with explicit recipient nodes and base WAF
// policies. Missing/unsupported inputs fail the whole candidate, without partial
// artifacts. It neither reads live selectors nor invents trusted recipients.
func Compile(ctx context.Context, configuration configmodel.Configuration, policies []PolicyRevision, opts Options) (*Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	// Decode into a fresh document: normalizing a shallow Go value can reuse
	// nested slices, while callers must retain ownership of their input graph.
	rawConfiguration, err := configmodel.CanonicalJSON(configuration)
	if err != nil {
		return nil, err
	}
	doc, err := configmodel.ParseConfiguration(bytes.NewReader(rawConfiguration), configmodel.JSON)
	if err != nil {
		return nil, err
	}
	configuration = doc.Configuration
	if len(configuration.ProfileAssignments) != 0 {
		return nil, fmt.Errorf("profile assignments require independently frozen materialization")
	}
	if len(policies) > MaxGateways {
		return nil, fmt.Errorf("policy capacity exceeded")
	}
	policyMap := make(map[string]PolicyRevision, len(policies))
	for _, p := range policies {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !configmodel.ValidID(p.RevisionID) || !configmodel.ValidDigest(p.ContentDigest) || policyMap[p.RevisionID].RevisionID != "" {
			return nil, fmt.Errorf("invalid or duplicate policy revision")
		}
		raw, e := configmodel.CanonicalJSON(p.Policy)
		if e != nil {
			return nil, e
		}
		checked, e := configmodel.ParseWafPolicy(bytes.NewReader(raw), configmodel.JSON)
		if e != nil {
			return nil, e
		}
		digest, e := configmodel.Digest(checked)
		if e != nil || digest != p.ContentDigest || checked.Metadata.SiteID != opts.SiteID || checked.Spec.RulesetVersionID != opts.RulesetVersionID || len(checked.Spec.Exceptions) != 0 {
			return nil, fmt.Errorf("policy digest, Site or unsupported exception mismatch")
		}
		p.Policy = *checked
		policyMap[p.RevisionID] = p
	}
	compilerDigest, err := configmodel.Digest(struct{ Version, Build, Renderer string }{CompilerVersion, opts.BuildDigest, wafnative.RendererVersion})
	if err != nil {
		return nil, err
	}
	out := &Candidate{APIVersion: CandidateVersion, Purpose: "unsigned_service_configuration_candidate", CompilerVersion: CompilerVersion, CompilerDigest: compilerDigest, ConfigurationDigest: doc.Digest, NodeID: opts.NodeID, SiteID: opts.SiteID, RevisionID: opts.RevisionID, GenerationID: opts.GenerationID, ComponentProfileRef: opts.ComponentProfileRef, RulesetVersionID: opts.RulesetVersionID, Gateways: []Gateway{}, SecretVersionIDs: []string{}, Artifacts: []Artifact{}, Blockers: []string{
		"independent_service_qualification_required",
		"sealed_source_projection_and_recipient_authority_required",
		"verified_component_repository_and_qualified_renderer_required",
		"immutable_secret_materialization_required",
		"central_access_policy_and_restriction_projection_required",
		"application_cookie_policy_required",
		"edge_transport_timeouts_and_tls_policy_required",
		"edge_identity_state_and_generation_lifecycle_required",
		"monitoring_and_log_lifecycle_required",
		"native_activation_probe_and_layout_binding_required",
	}}
	secrets, hosts := map[string]bool{}, map[string]bool{}
	var servers strings.Builder
	routes := 0
	for _, g := range configuration.Gateways {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if g.Metadata.SiteID != opts.SiteID {
			continue
		}
		if g.Spec.NodeSelector.MatchLabels != nil {
			return nil, fmt.Errorf("label selectors require independently frozen recipients")
		}
		if !contains(g.Spec.NodeSelector.NodeIDs, opts.NodeID) {
			continue
		}
		if g.Spec.Ownership != "managed" {
			return nil, fmt.Errorf("adopted Gateway requires verified ownership projection")
		}
		if g.Spec.ComponentProfileRef != opts.ComponentProfileRef {
			return nil, fmt.Errorf("component profile mismatch")
		}
		if g.Spec.WAF.Mode != "detection" && g.Spec.WAF.Mode != "blocking" {
			return nil, fmt.Errorf("mandatory WAF minimum is detection")
		}
		p, ok := policyMap[g.Spec.WAF.PolicyRevisionID]
		if !ok {
			return nil, fmt.Errorf("exact WAF policy revision is missing")
		}
		secrets[g.Spec.TLS.CertificateVersionID] = true
		byHost := map[string][]configmodel.Route{}
		for _, r := range g.Spec.Routes {
			if len(r.WAFExceptionIDs) != 0 {
				return nil, fmt.Errorf("route exceptions require independently qualified lineage")
			}
			if r.Upstream.TLS.CASecretVersionID != "" {
				secrets[r.Upstream.TLS.CASecretVersionID] = true
			}
			byHost[r.Hostname] = append(byHost[r.Hostname], r)
			routes++
		}
		if routes > MaxRoutes {
			return nil, fmt.Errorf("candidate route capacity exceeded")
		}
		// Central Auth registers exactly one origin/callback per Gateway ID.
		// Emitting a second origin under that identity would produce a handoff
		// that cannot be redeemed against the real registration contract.
		if len(byHost) != 1 {
			return nil, fmt.Errorf("a Gateway requires exactly one hostname for its registered authentication origin")
		}
		ordered := make([]string, 0, len(byHost))
		for host := range byHost {
			ordered = append(ordered, host)
		}
		sort.Strings(ordered)
		for _, host := range ordered {
			if hosts[host] {
				return nil, fmt.Errorf("hostname belongs to multiple Gateways")
			}
			hosts[host] = true
			if len(out.Gateways) >= MaxGateways {
				return nil, fmt.Errorf("candidate Gateway/host capacity exceeded")
			}
			part, server, e := compileHost(g, host, byHost[host], p, opts)
			if e != nil {
				return nil, e
			}
			out.Gateways = append(out.Gateways, part.gateway)
			out.Artifacts = append(out.Artifacts, part.artifacts...)
			servers.WriteString(server)
		}
	}
	if len(out.Gateways) == 0 {
		return nil, fmt.Errorf("node has no explicitly selected managed Gateway")
	}
	if len(secrets) > 100 {
		return nil, fmt.Errorf("candidate secret capacity exceeded")
	}
	for id := range secrets {
		out.SecretVersionIDs = append(out.SecretVersionIDs, id)
	}
	sort.Strings(out.SecretVersionIDs)
	// No worker uid, systemd unit, root helper layout or permission is inferred.
	// The unsigned candidate can be run privately for qualification only.
	native := fmt.Sprintf("load_module %s/modules/ngx_http_modsecurity_module.so;\npid %s/nginx.pid;\nerror_log stderr notice;\nworker_processes 1;\nevents { worker_connections 128; }\nhttp {\n    access_log off;\n    client_max_body_size 64k;\n    client_body_temp_path %s;\n    proxy_temp_path %s;\n    server { listen %s ssl default_server; ssl_reject_handshake on; return 421; }\n%s}\n", opts.RuntimeRoot, opts.RunDir, opts.RunDir, opts.RunDir, opts.ListenAddress, servers.String())
	out.Artifacts = append(out.Artifacts, artifact("nginx.conf", native))
	sort.Slice(out.Artifacts, func(i, j int) bool { return out.Artifacts[i].Path < out.Artifacts[j].Path })
	bytes := 0
	for _, a := range out.Artifacts {
		bytes += len(a.Content)
		if bytes > MaxArtifactBytes {
			return nil, fmt.Errorf("candidate artifact capacity exceeded")
		}
	}
	out.CandidateDigest, err = configmodel.Digest(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type compiledHost struct {
	gateway   Gateway
	artifacts []Artifact
}

func compileHost(g configmodel.Gateway, host string, routes []configmodel.Route, p PolicyRevision, o Options) (compiledHost, string, error) {
	id := strings.TrimPrefix(configmodel.DigestBytes([]byte(o.NodeID+"\n"+g.Metadata.ID+"\n"+host+"\n"+o.GenerationID)), "sha256:")[:24]
	listen, _ := netip.ParseAddrPort(o.ListenAddress)
	authority := host
	if listen.Port() != 443 {
		authority += ":" + strconv.Itoa(int(listen.Port()))
	}
	edge := edgeauth.Config{NodeID: o.NodeID, GatewayID: g.Metadata.ID, Origin: "https://" + authority, LoginOrigin: o.LoginOrigin, CentralOrigin: o.CentralOrigin, DeploymentGeneration: o.GenerationID, Routes: []edgeauth.Route{}, SocketPath: o.RunDir + "/edge-" + id + ".sock", StatePath: o.StateDir + "/edge-" + id + ".db", ClientCertificateFile: o.ClientCertificateFile, ClientKeyFile: o.ClientKeyFile, ServerCAFile: o.ServerCAFile}
	for _, route := range routes {
		u, err := url.Parse(route.Upstream.URL)
		if err != nil || (u.Path != "" && u.Path != "/") {
			return compiledHost{}, "", fmt.Errorf("upstream path rewrites are unsupported by EdgeAuth")
		}
		edge.Routes = append(edge.Routes, edgeauth.Route{ID: route.ID, PathPrefix: route.Path, Upstream: route.Upstream.URL, ApplicationCookies: []string{}})
	}
	if err := edge.Validate(); err != nil {
		return compiledHost{}, "", err
	}
	login, _ := url.Parse(o.LoginOrigin)
	central, _ := url.Parse(o.CentralOrigin)
	if host == central.Hostname() || host == login.Hostname() {
		return compiledHost{}, "", fmt.Errorf("application cannot use central or login hostname")
	}
	server, err := nginx.GenerateEdgeGatewayServerWithTLS(edge.Origin, edge.SocketPath, o.SecretDir+"/"+g.Spec.TLS.CertificateVersionID+"/certificate.pem", o.SecretDir+"/"+g.Spec.TLS.CertificateVersionID+"/private.key")
	if err != nil {
		return compiledHost{}, "", err
	}
	port := strconv.Itoa(int(listen.Port()))
	server = strings.Replace(server, "listen "+port+" ssl;", "listen "+o.ListenAddress+" ssl;", 1)
	const appLocation = "    location / {\n"
	if strings.Count(server, appLocation) != 1 {
		return compiledHost{}, "", fmt.Errorf("unexpected EdgeAuth generator contract")
	}
	wafName := "waf/" + id + ".conf"
	server = strings.Replace(server, appLocation, appLocation+"        modsecurity on;\n        modsecurity_rules_file "+o.GenerationRoot+"/"+wafName+";\n", 1)
	waf, err := wafnative.Render(p.Policy, g.Spec.WAF.Mode, o.RuntimeRoot, o.RunDir)
	if err != nil {
		return compiledHost{}, "", err
	}
	edgeRaw, err := configmodel.CanonicalJSON(edge)
	if err != nil {
		return compiledHost{}, "", err
	}
	return compiledHost{gateway: Gateway{GatewayID: g.Metadata.ID, Hostname: host, Edge: edge, Routes: routes, WAFPolicyRevisionID: p.RevisionID, WAFPolicyDigest: p.ContentDigest}, artifacts: []Artifact{artifact("edge/"+id+".json", string(edgeRaw)), artifact(wafName, waf)}}, server, nil
}

func validateOptions(o Options) error {
	for _, id := range []string{o.NodeID, o.SiteID, o.RevisionID, o.GenerationID, o.ComponentProfileRef.ID, o.RulesetVersionID} {
		if !configmodel.ValidID(id) {
			return fmt.Errorf("valid immutable candidate identity is required")
		}
	}
	if !configmodel.ValidDigest(o.BuildDigest) || !configmodel.ValidDigest(o.ComponentProfileRef.Digest) {
		return fmt.Errorf("immutable build/profile digest is required")
	}
	for _, p := range []string{o.GenerationRoot, o.RuntimeRoot, o.RunDir, o.StateDir, o.SecretDir, o.ClientCertificateFile, o.ClientKeyFile, o.ServerCAFile} {
		if !validAbsolutePath(p) {
			return fmt.Errorf("simple canonical absolute installation path is required")
		}
	}
	// Leave room for the generated suffix and Linux sockaddr_un terminator.
	if len(o.RunDir)+len("/edge-")+24+len(".sock") > 100 {
		return fmt.Errorf("EdgeAuth Unix socket path exceeds portable limit")
	}
	a, err := netip.ParseAddrPort(o.ListenAddress)
	if err != nil || !a.Addr().Is4() || a.Port() == 0 || a.String() != o.ListenAddress {
		return fmt.Errorf("canonical IPv4 listen address and nonzero port are required")
	}
	return nil
}

func artifact(p, content string) Artifact {
	return Artifact{Path: p, Content: content, Digest: configmodel.DigestBytes([]byte(content))}
}
func contains(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
