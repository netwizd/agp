// Package wafnative implements the qualified ModSecurity provider. It executes
// only authenticated component bytes in a private validation workspace, never
// installs, reloads a live Nginx or changes a managed node.
package wafnative

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/repository"
)

const RendererVersion = "agp.modsecurity-renderer/v1"

// VerifiedClock must obtain fresh challenge-bound time from the independent
// journal client. A CP wall-clock fallback is deliberately not provided.
type VerifiedClock func(context.Context) (time.Time, error)

type Provider struct {
	Store          repository.Store
	CompilerDigest string
	Clock          VerifiedClock
	// TempDir is installation-owned scratch, not an API request field.
	TempDir string
}

// ErrBusy means the process already has a native WAF operation in flight.
// Callers may retry; work is rejected before repository reads or scratch writes.
var ErrBusy = errors.New("native_waf_busy")

// Current also reads the complete trusted closure, so it shares the same limit
// as native validation across all Provider instances in this process.
var nativeWorkSlots = make(chan struct{}, 1)

func admitNativeWork(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case nativeWorkSlots <- struct{}{}:
		return func() { <-nativeWorkSlots }, nil
	default:
		return nil, ErrBusy
	}
}

func required() error {
	return fmt.Errorf("%w: native_qualification_required", repository.ErrUntrusted)
}
func (p *Provider) load(ctx context.Context) (*repository.VerifiedRelease, *repository.QualifiedProfile, time.Time, error) {
	if p == nil || p.Clock == nil || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(p.CompilerDigest) {
		return nil, nil, time.Time{}, required()
	}
	now, e := p.Clock(ctx)
	if e != nil || now.IsZero() {
		return nil, nil, time.Time{}, required()
	}
	v, e := p.Store.Current(ctx, now)
	if e != nil {
		return nil, nil, time.Time{}, required()
	}
	profile, e := v.QualifiedProfile(now)
	if e != nil {
		return nil, nil, time.Time{}, required()
	}
	// This is one qualified compatibility matrix row, not a universal renderer.
	t := profile.Profile.Tuple
	if t.Nginx != "1.30.8" || t.Connector != "1.0.4" || t.LibModSecurity != "3.0.17" || t.CRS != "4.30.0" || profile.Profile.LoaderPath != "lib/ld-linux-x86-64.so.2" || profile.Profile.NginxPath != "bin/nginx" || profile.Profile.ModulePath != "modules/ngx_http_modsecurity_module.so" || profile.Profile.UnicodePath != "share/modsecurity/unicode.mapping" || profile.Profile.RulesPath != "share/crs/rules" {
		return nil, nil, time.Time{}, required()
	}
	return v, profile, now, nil
}
func proofID(q configuration.WAFQualification) string {
	q.ID = ""
	b, _ := json.Marshal(q)
	return "wafq_" + strings.TrimPrefix(repository.Hash(b), "sha256:")
}
func (p *Provider) Current(ctx context.Context, q *configuration.WAFQualification) error {
	release, err := admitNativeWork(ctx)
	if err != nil {
		return err
	}
	defer release()
	return p.current(ctx, q)
}

// current rechecks a proof while the caller already owns native admission.
// ValidatePolicy retains its slot through the post-validation freshness check.
func (p *Provider) current(ctx context.Context, q *configuration.WAFQualification) error {
	if p == nil || q == nil || q.CompilerDigest != p.CompilerDigest || q.ID != proofID(*q) {
		return required()
	}
	v, profile, now, e := p.load(ctx)
	if e != nil || q == nil {
		return required()
	}
	if !now.Before(q.ExpiresAt) || q.ExpiresAt.After(v.ExpiresAt) || q.ManifestDigest != v.ManifestDigest || q.ReleaseSequence != v.Manifest.Signed.Sequence || q.RulesetVersionID != profile.Profile.RulesetVersionID || q.RulesetDigest != profile.RulesetDigest || q.ProfileID != profile.Profile.ID || q.ProfileDigest != profile.ProfileDigest || q.TupleDigest != profile.TupleDigest || q.EvidenceDigest != profile.EvidenceDigest || q.CompilerDigest != p.CompilerDigest || q.ID != proofID(*q) {
		return required()
	}
	return nil
}
func (p *Provider) ValidatePolicy(ctx context.Context, policy configmodel.WafPolicy) (*configuration.WAFQualification, error) {
	release, err := admitNativeWork(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	v, profile, now, e := p.load(ctx)
	if e != nil {
		return nil, e
	}
	raw, e := configmodel.CanonicalJSON(policy)
	if e != nil {
		return nil, e
	}
	checked, e := configmodel.ParseWafPolicy(bytes.NewReader(raw), configmodel.JSON)
	if e != nil {
		return nil, e
	}
	if checked.Spec.RulesetVersionID != profile.Profile.RulesetVersionID || len(checked.Spec.Exceptions) != 0 {
		return nil, required()
	}
	work, e := os.MkdirTemp(p.TempDir, "agp-waf-validation-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(work)
	if e = materialize(v, profile.Profile, work); e != nil {
		return nil, e
	}
	// Execute the exact renderer artifact that passed the signed functional
	// corpus. The currently embedded offline renderer cannot reuse old evidence.
	renderer, ok := v.Object(profile.Evidence.RendererDigest)
	if !ok || repository.Hash(renderer) != profile.Evidence.RendererDigest {
		return nil, required()
	}
	if e = os.WriteFile(filepath.Join(work, "qualified-renderer"), renderer, 0500); e != nil {
		return nil, e
	}
	// Both supported assignment modes must parse against the exact real tuple.
	for _, mode := range []string{"detection", "blocking"} {
		if e = checkPolicy(ctx, *checked, mode, work); e != nil {
			return nil, e
		}
	}
	contentDigest, e := configmodel.Digest(checked)
	if e != nil {
		return nil, e
	}
	expires := now.Add(30 * time.Minute).UTC().Truncate(time.Microsecond)
	if v.ExpiresAt.Before(expires) {
		expires = v.ExpiresAt
	}
	q := &configuration.WAFQualification{ContentDigest: contentDigest, ManifestDigest: v.ManifestDigest, ReleaseSequence: v.Manifest.Signed.Sequence, RulesetVersionID: profile.Profile.RulesetVersionID, RulesetDigest: profile.RulesetDigest, ProfileID: profile.Profile.ID, ProfileDigest: profile.ProfileDigest, TupleDigest: profile.TupleDigest, EvidenceDigest: profile.EvidenceDigest, CompilerDigest: p.CompilerDigest, ExpiresAt: expires}
	q.ID = proofID(*q)
	// Metadata, independent time and artifact bytes are checked again after the
	// potentially long native validation. No pre-validation lease is reused.
	if e = p.current(ctx, q); e != nil {
		return nil, e
	}
	return q, nil
}
func materialize(v *repository.VerifiedRelease, p repository.ComponentProfile, work string) error {
	for _, entry := range p.Files {
		raw, ok := v.Object(entry.Digest)
		if !ok || repository.Hash(raw) != entry.Digest {
			return required()
		}
		name := filepath.Join(work, filepath.FromSlash(entry.Path))
		if e := os.MkdirAll(filepath.Dir(name), 0700); e != nil {
			return e
		}
		mode := os.FileMode(0400)
		if entry.Path == p.NginxPath || entry.Path == p.LoaderPath {
			mode = 0500
		}
		f, e := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if e != nil {
			return e
		}
		_, e = f.Write(raw)
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return errors.Join(e, closeErr)
		}
	}
	return nil
}

type boundedOutput struct {
	b     bytes.Buffer
	total int
}

func (w *boundedOutput) Write(b []byte) (int, error) {
	n := len(b)
	w.total += n
	if remaining := 64<<10 - w.b.Len(); remaining > 0 {
		w.b.Write(b[:min(remaining, len(b))])
	}
	return n, nil
}
func checkPolicy(ctx context.Context, policy configmodel.WafPolicy, mode, work string) error {
	policyRaw, e := configmodel.CanonicalJSON(policy)
	if e != nil {
		return e
	}
	policyPath := filepath.Join(work, "policy.json")
	if e = os.WriteFile(policyPath, policyRaw, 0600); e != nil {
		return e
	}
	limited, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	renderer := exec.CommandContext(limited, filepath.Join(work, "lib/ld-linux-x86-64.so.2"), "--library-path", filepath.Join(work, "lib"), filepath.Join(work, "qualified-renderer"), "waf-render", "--policy", policyPath, "--bundle", work, "--work", work, "--mode", mode)
	renderer.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var rendered, diagnostic boundedOutput
	renderer.Stdout, renderer.Stderr = &rendered, &diagnostic
	if e = renderer.Run(); e != nil || rendered.total > 64<<10 || rendered.b.Len() == 0 {
		return fmt.Errorf("%w: qualified renderer rejected policy", repository.ErrUntrusted)
	}
	if e = os.WriteFile(filepath.Join(work, "policy.conf"), rendered.b.Bytes(), 0600); e != nil {
		return e
	}
	nginx := fmt.Sprintf("load_module %s/modules/ngx_http_modsecurity_module.so;\npid %s/nginx.pid;\nerror_log stderr notice;\nevents {}\nhttp { access_log off; client_body_temp_path %s; server { listen 127.0.0.1:18080; modsecurity on; modsecurity_rules_file %s/policy.conf; location / { return 204; } } }\n", work, work, work, work)
	if e = os.WriteFile(filepath.Join(work, "nginx.conf"), []byte(nginx), 0600); e != nil {
		return e
	}
	cmd := exec.CommandContext(limited, filepath.Join(work, "lib/ld-linux-x86-64.so.2"), "--library-path", filepath.Join(work, "lib"), filepath.Join(work, "bin/nginx"), "-p", work+"/", "-c", filepath.Join(work, "nginx.conf"), "-t")
	// No inherited LD_PRELOAD, shell, remote include or caller-supplied argv.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var output boundedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("%w: native policy configuration rejected", repository.ErrUntrusted)
	}
	if !strings.Contains(output.b.String(), "test is successful") {
		return required()
	}
	return nil
}

var simplePath = regexp.MustCompile(`^/[A-Za-z0-9/_.+-]+$`)

// Render accepts only the typed supported policy. Neither metadata, comments,
// rule IDs nor arbitrary native fragments are interpolated into directives.
func Render(policy configmodel.WafPolicy, mode, bundle, work string) (string, error) {
	raw, e := configmodel.CanonicalJSON(policy)
	if e != nil {
		return "", e
	}
	p, e := configmodel.ParseWafPolicy(bytes.NewReader(raw), configmodel.JSON)
	if e != nil {
		return "", e
	}
	if len(p.Spec.Exceptions) != 0 {
		return "", required()
	}
	if !simplePath.MatchString(bundle) || !simplePath.MatchString(work) || filepath.Clean(bundle) != bundle || filepath.Clean(work) != work {
		return "", required()
	}
	engine := map[string]string{"off": "Off", "detection": "DetectionOnly", "blocking": "On"}[mode]
	if engine == "" {
		return "", required()
	}
	return fmt.Sprintf(`SecRuleEngine %s
SecRequestBodyAccess On
SecRequestBodyLimit 65536
SecRequestBodyNoFilesLimit 65536
SecRequestBodyLimitAction Reject
SecRequestBodyJsonDepthLimit 64
SecArgumentsLimit 1000
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html application/json
SecResponseBodyLimit 65536
SecResponseBodyLimitAction Reject
SecTmpDir %s
SecDataDir %s
SecUploadKeepFiles Off
SecAuditEngine Off
SecUnicodeMapFile %s/share/modsecurity/unicode.mapping 20127
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
SecRule REQUEST_HEADERS:Content-Type "^application/(?:[a-z0-9.-]+[+])?json(?:;|$)" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body'"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,t:none,log,deny,status:400,msg:'Multipart strict validation failed'"
SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" "id:200004,phase:2,t:none,log,deny,status:400,msg:'Multipart unmatched boundary'"
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"
SecAction "id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=4300"
Include %s/share/crs/rules/*.conf
`, engine, work, work, bundle, p.Spec.ParanoiaLevel, p.Spec.ParanoiaLevel, p.Spec.InboundAnomalyThreshold, p.Spec.OutboundAnomalyThreshold, bundle), nil
}

// ReadPolicy is shared by the offline renderer and the HTTP-independent lab.
func ReadPolicy(r io.Reader) (*configmodel.WafPolicy, error) {
	return configmodel.ParseWafPolicy(r, configmodel.JSON)
}
