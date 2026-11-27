package repository

import (
	"path"
	"strings"
	"time"
)

type ComponentTuple struct {
	Nginx          string   `json:"nginx"`
	Connector      string   `json:"connector"`
	LibModSecurity string   `json:"libmodsecurity"`
	CRS            string   `json:"crs"`
	BuildFlags     []string `json:"buildFlags"`
	ABIDigest      string   `json:"abiDigest"`
}
type ProfileFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}
type ComponentProfile struct {
	APIVersion       string         `json:"apiVersion"`
	ID               string         `json:"id"`
	Platform         Platform       `json:"platform"`
	Tuple            ComponentTuple `json:"tuple"`
	RulesetVersionID string         `json:"rulesetVersionId"`
	Files            []ProfileFile  `json:"files"`
	LoaderPath       string         `json:"loaderPath"`
	NginxPath        string         `json:"nginxPath"`
	ModulePath       string         `json:"modulePath"`
	UnicodePath      string         `json:"unicodePath"`
	RulesPath        string         `json:"rulesPath"`
}
type QualificationCheck struct {
	ID     string `json:"id"`
	Passed bool   `json:"passed"`
}
type QualificationEvidence struct {
	APIVersion         string               `json:"apiVersion"`
	ProfileDigest      string               `json:"profileDigest"`
	TupleDigest        string               `json:"tupleDigest"`
	CorpusDigest       string               `json:"corpusDigest"`
	HarnessDigest      string               `json:"harnessDigest"`
	RendererDigest     string               `json:"rendererDigest"`
	NativeReportDigest string               `json:"nativeReportDigest"`
	Platform           Platform             `json:"platform"`
	HostKernel         string               `json:"hostKernel"`
	StartedAt          time.Time            `json:"startedAt"`
	CompletedAt        time.Time            `json:"completedAt"`
	Checks             []QualificationCheck `json:"checks"`
}
type SBOMFile struct {
	Path    string `json:"path"`
	Digest  string `json:"digest"`
	License string `json:"license"`
}
type SBOM struct {
	APIVersion string     `json:"apiVersion"`
	Files      []SBOMFile `json:"files"`
}
type QualifiedProfile struct {
	Profile        ComponentProfile
	ProfileDigest  string
	TupleDigest    string
	Evidence       QualificationEvidence
	EvidenceDigest string
	RulesetDigest  string
}

var RequiredNativeChecks = []string{
	"nginx_config_valid", "benign_allow", "detection_logs_attack",
	"blocking_query", "blocking_urlencoded", "blocking_json", "blocking_multipart",
	"response_body", "neighbour_isolation", "invalid_config_rejected",
	"raw_directive_rejected", "expired_exception_rejected", "threshold_effect", "paranoia_effect",
	"off_mode", "blocking_sql_query", "malformed_json_rejected", "request_body_limit",
	"paranoia_level_3", "paranoia_level_4", "outbound_threshold_effect", "detection_response_body",
	"upstream_not_reached", "body_bytes_not_forwarded", "wrong_module_abi",
}

func validPath(p string) bool {
	if p == "" || len(p) > 256 || strings.HasPrefix(p, "/") || path.Clean(p) != p || p == "." || p == ".." || strings.HasPrefix(p, "../") || strings.ContainsAny(p, "\\\x00\r\n\t ") {
		return false
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/_.+-", c)) {
			return false
		}
	}
	return true
}

// QualifiedProfile binds the independent signed native report, compatibility
// profile, runtime bytes and license inventory through the verified closure.
func (v *VerifiedRelease) QualifiedProfile(now time.Time) (*QualifiedProfile, error) {
	if !now.Before(v.ExpiresAt) {
		return nil, reject("expired release")
	}
	m := v.Manifest.Signed
	var p ComponentProfile
	if e := strict(v.objects[m.CompatibilityProfile.Digest], &p); e != nil {
		return nil, e
	}
	if p.APIVersion != "agp.component-profile/v1alpha1" || p.ID != m.CompatibilityProfile.ID || p.Platform != m.Platform || !idPattern.MatchString(p.RulesetVersionID) || p.Tuple.Nginx == "" || p.Tuple.Connector == "" || p.Tuple.LibModSecurity == "" || p.Tuple.CRS == "" || !digestPattern.MatchString(p.Tuple.ABIDigest) || len(p.Tuple.BuildFlags) == 0 || len(p.Tuple.BuildFlags) > 64 || len(p.Files) == 0 || len(p.Files) > 1000 {
		return nil, reject("component profile contract")
	}
	for _, flag := range p.Tuple.BuildFlags {
		if len(flag) == 0 || len(flag) > 1024 || strings.ContainsAny(flag, "\x00\r\n") {
			return nil, reject("build flags")
		}
	}
	files := map[string]string{}
	for _, f := range p.Files {
		if !validPath(f.Path) || !digestPattern.MatchString(f.Digest) || files[f.Path] != "" {
			return nil, reject("runtime file path")
		}
		if _, ok := v.objects[f.Digest]; !ok {
			return nil, reject("missing runtime file")
		}
		files[f.Path] = f.Digest
	}
	for _, f := range []string{p.LoaderPath, p.NginxPath, p.ModulePath, p.UnicodePath} {
		if files[f] == "" {
			return nil, reject("missing required runtime component")
		}
	}
	if !validPath(p.RulesPath) {
		return nil, reject("rules directory")
	}
	rules := map[string]string{}
	for name, digest := range files {
		if strings.HasPrefix(name, p.RulesPath+"/") {
			rules[name] = digest
		}
	}
	if len(rules) == 0 {
		return nil, reject("missing CRS")
	}
	rulesRaw, e := canonical(rules)
	if e != nil {
		return nil, e
	}
	tupleRaw, e := canonical(p.Tuple)
	if e != nil {
		return nil, e
	}
	tupleDigest := Hash(tupleRaw)
	var evidence *QualificationEvidence
	evidenceDigest := ""
	for _, a := range m.Artifacts {
		if a.MediaType != "application/vnd.agp.waf-qualification+json" {
			continue
		}
		if evidence != nil {
			return nil, reject("ambiguous native evidence")
		}
		evidence = &QualificationEvidence{}
		evidenceDigest = "sha256:" + a.SHA256
		if e = strict(v.objects[evidenceDigest], evidence); e != nil {
			return nil, e
		}
	}
	if evidence == nil || evidence.APIVersion != "agp.waf-qualification/v1alpha1" || evidence.ProfileDigest != m.CompatibilityProfile.Digest || evidence.TupleDigest != tupleDigest || evidence.Platform != m.Platform || !digestPattern.MatchString(evidence.CorpusDigest) || !digestPattern.MatchString(evidence.HarnessDigest) || !digestPattern.MatchString(evidence.RendererDigest) || !digestPattern.MatchString(evidence.NativeReportDigest) || evidence.HostKernel == "" || evidence.StartedAt.IsZero() || evidence.CompletedAt.Before(evidence.StartedAt) || evidence.CompletedAt.After(m.CreatedAt) || len(evidence.Checks) > 128 {
		return nil, reject("native qualification evidence")
	}
	passed := map[string]bool{}
	for _, c := range evidence.Checks {
		if !idPattern.MatchString(c.ID) || passed[c.ID] || !c.Passed {
			return nil, reject("native qualification failure")
		}
		passed[c.ID] = true
	}
	for _, c := range RequiredNativeChecks {
		if !passed[c] {
			return nil, reject("incomplete native qualification")
		}
	}
	// Corpus and harness bytes are part of this same signed dependency closure.
	for _, d := range []string{evidence.CorpusDigest, evidence.HarnessDigest, evidence.RendererDigest, evidence.NativeReportDigest} {
		if _, ok := v.objects[d]; !ok {
			return nil, reject("missing qualification source")
		}
	}
	var sbom SBOM
	if e = strict(v.objects[m.SBOMDigest], &sbom); e != nil {
		return nil, e
	}
	if sbom.APIVersion != "agp.sbom/v1alpha1" || len(sbom.Files) != len(files) {
		return nil, reject("SBOM coverage")
	}
	for _, entry := range sbom.Files {
		if files[entry.Path] != entry.Digest || entry.License == "" || len(entry.License) > 256 {
			return nil, reject("SBOM file or license")
		}
		delete(files, entry.Path)
	}
	if len(files) != 0 {
		return nil, reject("incomplete SBOM")
	}
	return &QualifiedProfile{Profile: p, ProfileDigest: m.CompatibilityProfile.Digest, TupleDigest: tupleDigest, Evidence: *evidence, EvidenceDigest: evidenceDigest, RulesetDigest: Hash(rulesRaw)}, nil
}
