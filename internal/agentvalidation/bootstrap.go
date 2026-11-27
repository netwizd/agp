package agentvalidation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nativesandbox"
	"github.com/netwizd/agp/internal/ownedtree"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/securityjournal"
)

const BootstrapProfile = "agp.managed-bootstrap/v1alpha1"
const BootstrapCandidateVersion = "agp.baseline-candidate/v1alpha1"

// This closed profile is generated for the same filesystem view used by the
// validator and the future managed service. It accepts no application traffic.
// Existing adopted configurations cannot be translated into it implicitly.
const bootstrapConfig = `load_module /runtime/modules/ngx_http_modsecurity_module.so;
worker_processes 1;
pid /scratch/nginx.pid;
error_log stderr notice;
events { worker_connections 16; }
http {
    access_log off;
    client_body_temp_path /scratch/client;
    proxy_temp_path /scratch/proxy;
    fastcgi_temp_path /scratch/fastcgi;
    uwsgi_temp_path /scratch/uwsgi;
    scgi_temp_path /scratch/scgi;
    server {
        listen 127.0.0.1:18080 default_server;
        server_name _;
        location / { return 503; }
    }
}
`

func ManagedBootstrapConfig() []byte { return []byte(bootstrapConfig) }

type BootstrapAuthority interface {
	Head(context.Context) (securityjournal.Head, error)
}

// BootstrapCandidate is syntax evidence for a captured, closed bootstrap only.
// It has no revision ID and cannot be used as a plan's verified baseline.
type BootstrapCandidate struct {
	APIVersion                  string                 `json:"apiVersion"`
	Purpose                     string                 `json:"purpose"`
	Provenance                  string                 `json:"provenance"`
	CandidateDigest             string                 `json:"candidateDigest"`
	NodeID                      string                 `json:"nodeId"`
	SiteID                      string                 `json:"siteId"`
	OwnershipDigest             string                 `json:"ownershipDigest"`
	TreeDigest                  string                 `json:"treeDigest"`
	BundleDigest                string                 `json:"bundleDigest"`
	BootstrapProfile            string                 `json:"bootstrapProfile"`
	BootstrapProfileDigest      string                 `json:"bootstrapProfileDigest"`
	Pins                        Pins                   `json:"pins"`
	SandboxToolDigest           string                 `json:"sandboxToolDigest"`
	SandboxProfileDigest        string                 `json:"sandboxProfileDigest"`
	ExecutionUID                int                    `json:"executionUid"`
	ExecutionGID                int                    `json:"executionGid"`
	ExecutionHost               inventory.OS           `json:"executionHost"`
	ExecutionBootDigest         string                 `json:"executionBootDigest"`
	RuntimeHostQualified        bool                   `json:"runtimeHostQualified"`
	AuthorityID                 string                 `json:"authorityId"`
	AuthorityEpoch              securityjournal.UInt63 `json:"authorityEpoch"`
	MinimumDenySequence         securityjournal.UInt63 `json:"minimumDenySequence"`
	CheckedAt                   time.Time              `json:"checkedAt"`
	ExpiresAt                   time.Time              `json:"expiresAt"`
	SyntaxValidated             bool                   `json:"syntaxValidated"`
	ActiveConfigurationVerified bool                   `json:"activeConfigurationVerified"`
	BaselineVerified            bool                   `json:"baselineVerified"`
	Deployable                  bool                   `json:"deployable"`
	NoApply                     bool                   `json:"noApply"`
}

// BootstrapValidator never modifies the observed tree or installs a service.
// Authority must be an independently pinned journal client, and Repository an
// installation-selected signed store. There is no task/HTTP source for paths.
type BootstrapValidator struct {
	Repository repository.Store
	Tree       *ownedtree.Tree
	Sandbox    *nativesandbox.Runner
	Authority  BootstrapAuthority
}

var ErrBootstrap = errors.New("bootstrap_candidate_unavailable")

func bootstrapSnapshot(ctx context.Context, tree *ownedtree.Tree) (*ownedtree.Snapshot, *ownedtree.Observation, error) {
	if tree == nil {
		return nil, nil, ErrBootstrap
	}
	snapshot, err := tree.Capture(ctx)
	if err != nil {
		return nil, nil, ErrBootstrap
	}
	ok := false
	defer func() {
		if !ok {
			_ = snapshot.Close()
		}
	}()
	view, err := snapshot.Observation()
	if err != nil || len(view.Entries) != 2 {
		return nil, nil, ErrBootstrap
	}
	for _, e := range view.Entries {
		if e.Path == "." && e.Kind == "directory" || e.Path == "nginx.conf" && e.Kind == "file" {
			continue
		}
		return nil, nil, ErrBootstrap
	}
	content, exists := snapshot.File("nginx.conf")
	defer clear(content)
	if !exists || !bytes.Equal(content, []byte(bootstrapConfig)) {
		return nil, nil, ErrBootstrap
	}
	ok = true
	return snapshot, view, nil
}

func (v *BootstrapValidator) Validate(ctx context.Context) (*BootstrapCandidate, error) {
	if v == nil || ctx == nil || v.Tree == nil || v.Sandbox == nil || v.Authority == nil || ctx.Err() != nil {
		return nil, ErrBootstrap
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	first, err := v.Authority.Head(ctx)
	if err != nil || first.RecordedAt.IsZero() || first.Epoch == 0 {
		return nil, ErrBootstrap
	}
	release, err := v.Repository.Current(ctx, first.RecordedAt)
	if err != nil {
		return nil, ErrBootstrap
	}
	profile, err := release.QualifiedProfile(first.RecordedAt)
	if err != nil || !bootstrapRuntime(profile) {
		return nil, ErrBootstrap
	}
	host, err := inventory.Collect(ctx, inventory.CollectorOptions{AgentVersion: "bootstrap-validator", DiskPath: "/"})
	if err != nil {
		return nil, ErrBootstrap
	}
	snapshot, observed, err := bootstrapSnapshot(ctx, v.Tree)
	if err != nil {
		return nil, err
	}
	defer snapshot.Close()
	work, err := os.MkdirTemp("/tmp", "agp-bootstrap-")
	if err != nil {
		return nil, ErrBootstrap
	}
	defer os.RemoveAll(work)
	runtimeDir, configDir := filepath.Join(work, "runtime"), filepath.Join(work, "config")
	if os.Mkdir(runtimeDir, 0700) != nil || os.Mkdir(configDir, 0700) != nil {
		return nil, ErrBootstrap
	}
	for _, f := range profile.Profile.Files {
		data, exists := release.Object(f.Digest)
		if !exists || repository.Hash(data) != f.Digest {
			clear(data)
			return nil, ErrBootstrap
		}
		name := filepath.Join(runtimeDir, filepath.FromSlash(f.Path))
		mode := os.FileMode(0400)
		if f.Path == profile.Profile.LoaderPath || f.Path == profile.Profile.NginxPath {
			mode = 0500
		}
		err = os.MkdirAll(filepath.Dir(name), 0700)
		if err == nil {
			err = writeNew(name, data, mode)
		}
		clear(data)
		if err != nil {
			return nil, ErrBootstrap
		}
	}
	config, _ := snapshot.File("nginx.conf")
	err = writeNew(filepath.Join(configDir, "nginx.conf"), config, 0400)
	clear(config)
	if err != nil {
		return nil, ErrBootstrap
	}
	if err = v.Sandbox.RunNginx(ctx, nativesandbox.Spec{RuntimeDir: runtimeDir, ConfigDir: configDir, LoaderPath: profile.Profile.LoaderPath, NginxPath: profile.Profile.NginxPath}); err != nil {
		return nil, ErrBootstrap
	}
	currentTree, err := v.Tree.Verify(ctx)
	if err != nil || currentTree.TreeDigest != observed.TreeDigest {
		return nil, ErrBootstrap
	}
	last, err := v.Authority.Head(ctx)
	if err != nil || !last.SameState(first) || last.RecordedAt.Before(first.RecordedAt) || !last.RecordedAt.Before(first.RecordedAt.Add(45*time.Second)) {
		return nil, ErrBootstrap
	}
	currentRelease, err := v.Repository.Current(ctx, last.RecordedAt)
	if err != nil || currentRelease.ManifestDigest != release.ManifestDigest || ctx.Err() != nil {
		return nil, ErrBootstrap
	}
	currentHost, err := inventory.Collect(ctx, inventory.CollectorOptions{AgentVersion: "bootstrap-validator", DiskPath: "/"})
	if err != nil || currentHost.BootID != host.BootID || currentHost.Capabilities.OS != host.Capabilities.OS {
		return nil, ErrBootstrap
	}
	currentTree, err = v.Tree.Verify(ctx)
	if err != nil || currentTree.TreeDigest != observed.TreeDigest || ctx.Err() != nil {
		return nil, ErrBootstrap
	}
	pins := Pins{release.ManifestDigest, profile.ProfileDigest, profile.TupleDigest, profile.EvidenceDigest, profile.Evidence.RendererDigest}
	bundle, err := configmodel.Digest(struct {
		APIVersion string `json:"apiVersion"`
		Profile    string `json:"profile"`
		Config     string `json:"configDigest"`
	}{"agp.bootstrap-bundle/v1alpha1", BootstrapProfile, configmodel.DigestBytes([]byte(bootstrapConfig))})
	if err != nil {
		return nil, ErrBootstrap
	}
	profileDigest, err := configmodel.Digest(struct{ ID, ConfigDigest string }{BootstrapProfile, configmodel.DigestBytes([]byte(bootstrapConfig))})
	if err != nil {
		return nil, ErrBootstrap
	}
	tool := v.Sandbox.Binding()
	if !configmodel.ValidDigest(tool.ToolDigest) || !configmodel.ValidDigest(tool.ProfileDigest) {
		return nil, ErrBootstrap
	}
	expires := last.RecordedAt.Add(5 * time.Minute)
	if release.ExpiresAt.Before(expires) {
		expires = release.ExpiresAt
	}
	out := &BootstrapCandidate{APIVersion: BootstrapCandidateVersion, Purpose: "baseline_candidate", Provenance: "managed_bootstrap", NodeID: observed.NodeID, SiteID: observed.SiteID, OwnershipDigest: observed.ManifestDigest, TreeDigest: observed.TreeDigest, BundleDigest: bundle, BootstrapProfile: BootstrapProfile, BootstrapProfileDigest: profileDigest, Pins: pins, SandboxToolDigest: tool.ToolDigest, SandboxProfileDigest: tool.ProfileDigest, AuthorityID: last.AuthorityID, AuthorityEpoch: last.Epoch, MinimumDenySequence: last.Sequence, CheckedAt: last.RecordedAt, ExpiresAt: expires, SyntaxValidated: true, ActiveConfigurationVerified: false, BaselineVerified: false, Deployable: false, NoApply: true}
	out.ExecutionHost = host.Capabilities.OS
	out.ExecutionUID = int(tool.ExecutionUID)
	out.ExecutionGID = int(tool.ExecutionGID)
	out.ExecutionBootDigest = configmodel.DigestBytes([]byte(host.BootID))
	out.RuntimeHostQualified = host.Capabilities.OS.ID == profile.Profile.Platform.OS && host.Capabilities.OS.VersionID == profile.Profile.Platform.OSVersion && host.Capabilities.OS.Architecture == profile.Profile.Platform.Arch && host.Capabilities.OS.Kernel == profile.Evidence.HostKernel
	out.CandidateDigest, err = configmodel.Digest(*out)
	if err != nil || ctx.Err() != nil {
		return nil, ErrBootstrap
	}
	return out, nil
}

func bootstrapRuntime(p *repository.QualifiedProfile) bool {
	if p == nil {
		return false
	}
	t := p.Profile.Tuple
	return t.Nginx == "1.30.8" && t.Connector == "1.0.4" && t.LibModSecurity == "3.0.17" && t.CRS == "4.30.0" && p.Profile.LoaderPath == "lib/ld-linux-x86-64.so.2" && p.Profile.NginxPath == "bin/nginx" && p.Profile.ModulePath == "modules/ngx_http_modsecurity_module.so"
}
