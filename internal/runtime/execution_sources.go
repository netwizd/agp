//go:build linux

package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/executionsources"
	"github.com/netwizd/agp/internal/helpertransport"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/rolloutexecution"
)

const ExecutionRuntimeVersion = "agp.execution-runtime/v1alpha1"

var ErrExecutionRuntime = errors.New("trusted execution runtime unavailable")

// ExecutionOptions contains public installation paths only. This file and the
// source catalog are root-owned and outside the CP database/restore directory.
// Secret-bearing signed materializations are kept separately, service-private.
type ExecutionOptions struct {
	APIVersion       string `json:"apiVersion"`
	SourceCatalog    string `json:"sourceCatalog"`
	MaterialsFile    string `json:"materialsFile"`
	WriterLockFile   string `json:"writerLockFile"`
	RepositoryDir    string `json:"repositoryDir"`
	RepositoryAnchor string `json:"repositoryAnchor"`
	PermitKeyID      string `json:"permitKeyId"`
	PermitKeyFile    string `json:"permitKeyFile"`
	ControlKeyID     string `json:"controlKeyId"`
	ControlKeyFile   string `json:"controlKeyFile"`
	JournalPublicKey string `json:"journalPublicKey"`
}

type ExecutionRuntime struct {
	Service *rolloutexecution.Service
	Sources *executionsources.Service
	lock    *helpertransport.WriterLock
}

func (r *ExecutionRuntime) Close() {
	if r != nil && r.lock != nil {
		_ = r.lock.Close()
	}
}

func executionKey(path string) (ed25519.PrivateKey, error) {
	raw, err := helpertransport.ReadPrivateFile(path, 8192)
	if err != nil {
		return nil, ErrExecutionRuntime
	}
	defer clear(raw)
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != "PRIVATE KEY" || len(b.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrExecutionRuntime
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, ErrExecutionRuntime
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrExecutionRuntime
	}
	return key, nil
}

func executionPublic(v string) (ed25519.PublicKey, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(v)
	if e != nil || len(b) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(b) != v {
		return nil, ErrExecutionRuntime
	}
	return ed25519.PublicKey(b), nil
}

// OpenExecutionRuntime is opt-in. Partial or invalid configuration is fatal;
// absence leaves all execution endpoints disabled. The caller must already
// hold the secure PostgreSQL identity lease through IdentityRuntime.
func OpenExecutionRuntime(ctx context.Context, identity *IdentityRuntime, agents *inventory.Service, origin string) (r *ExecutionRuntime, err error) {
	path := os.Getenv("AGP_EXECUTION_CONFIG")
	if path == "" {
		return nil, nil
	}
	if identity == nil || identity.Coordinator == nil || identity.Directory == nil || identity.Journal == nil || agents == nil || identity.ReleaseLease == nil {
		return nil, ErrExecutionRuntime
	}
	initial, e := helpertransport.ReadRootFile(path, false, 65536)
	if e != nil {
		return nil, ErrExecutionRuntime
	}
	var options ExecutionOptions
	if configmodel.StrictJSON(bytes.NewReader(initial), &options, 65536) != nil || options.APIVersion != ExecutionRuntimeVersion || !configmodel.ValidID(options.PermitKeyID) || !configmodel.ValidID(options.ControlKeyID) || options.PermitKeyID == options.ControlKeyID || options.MaterialsFile == "" || options.SourceCatalog == "" || options.RepositoryDir == "" || options.RepositoryAnchor == "" {
		return nil, ErrExecutionRuntime
	}
	journalPin, e := executionPublic(options.JournalPublicKey)
	if e != nil || !bytes.Equal(journalPin, identity.Journal.SigningPublicKey()) {
		return nil, ErrExecutionRuntime
	}
	lock, e := helpertransport.AcquireWriterLock(options.WriterLockFile)
	if e != nil {
		return nil, ErrExecutionRuntime
	}
	r = &ExecutionRuntime{lock: lock}
	opened := r
	defer func() {
		if err != nil {
			opened.Close()
		}
	}()
	permit, e := executionKey(options.PermitKeyFile)
	if e != nil {
		return nil, e
	}
	defer clear(permit)
	control, e := executionKey(options.ControlKeyFile)
	if e != nil {
		return nil, e
	}
	defer clear(control)
	if bytes.Equal(permit.Public().(ed25519.PublicKey), control.Public().(ed25519.PublicKey)) || bytes.Equal(permit.Public().(ed25519.PublicKey), journalPin) || bytes.Equal(control.Public().(ed25519.PublicKey), journalPin) {
		return nil, ErrExecutionRuntime
	}
	// Retain only public fingerprints in the long-lived witness, because the
	// service constructor makes its own private-key copy.
	permitPin := append(ed25519.PublicKey(nil), permit.Public().(ed25519.PublicKey)...)
	controlPin := append(ed25519.PublicKey(nil), control.Public().(ed25519.PublicKey)...)
	witness := func(call context.Context) error {
		if lock.Witness(call) != nil {
			return ErrExecutionRuntime
		}
		fresh, e := helpertransport.ReadRootFile(path, false, 65536)
		if e != nil || !bytes.Equal(initial, fresh) {
			return ErrExecutionRuntime
		}
		if _, e = helpertransport.ReadRootFile(options.RepositoryAnchor, false, int(repository.MaxMetadataBytes)); e != nil {
			return ErrExecutionRuntime
		}
		for _, v := range []struct {
			path string
			key  ed25519.PublicKey
		}{{options.PermitKeyFile, permitPin}, {options.ControlKeyFile, controlPin}} {
			fresh, e := executionKey(v.path)
			if e != nil {
				return ErrExecutionRuntime
			}
			equal := bytes.Equal(fresh.Public().(ed25519.PublicKey), v.key)
			clear(fresh)
			if !equal {
				return ErrExecutionRuntime
			}
		}
		return nil
	}
	load := func(call context.Context) (executionsources.Config, error) {
		var c executionsources.Config
		if witness(call) != nil {
			return c, ErrExecutionRuntime
		}
		public, e := helpertransport.ReadRootFile(options.SourceCatalog, false, executionsources.MaxCatalogBytes)
		if e != nil {
			return c, ErrExecutionRuntime
		}
		private, e := helpertransport.ReadPrivateFile(options.MaterialsFile, executionsources.MaxCatalogBytes)
		if e != nil {
			return c, ErrExecutionRuntime
		}
		defer clear(private)
		c, e = decodeExecutionFiles(public, private)
		if e != nil {
			return c, e
		}
		for _, encoded := range c.QualificationKeys {
			key, e := executionPublic(encoded)
			if e != nil || bytes.Equal(key, permitPin) || bytes.Equal(key, controlPin) || bytes.Equal(key, journalPin) {
				return c, ErrExecutionRuntime
			}
		}
		for _, binding := range c.Bindings {
			key, e := executionPublic(binding.Anchor.ReceiptPublicKey)
			if e != nil || bytes.Equal(key, permitPin) || bytes.Equal(key, controlPin) || bytes.Equal(key, journalPin) {
				return c, ErrExecutionRuntime
			}
		}
		return c, nil
	}
	r.Sources, e = executionsources.New(identity.Coordinator, agents, repository.Store{Dir: options.RepositoryDir, AnchorPath: options.RepositoryAnchor}, load, witness)
	if e != nil {
		return nil, ErrExecutionRuntime
	}
	r.Service, e = rolloutexecution.New(identity.Coordinator, r.Sources, rolloutexecution.Keys{PermitKeyID: options.PermitKeyID, PermitKey: permit, ControlKeyID: options.ControlKeyID, ControlKey: control}, origin)
	if e != nil {
		return nil, ErrExecutionRuntime
	}
	r.Service.WithDirectorySubjects(identity.Directory).WithAgentAuthenticator(agents.AuthenticateAgent)
	return r, nil
}

// Keep native persisted shapes out of the restricted HTTP DTO parser. These
// bytes still require Sources' qualification, installation and SQL admission.
func decodeExecutionFiles(public, private []byte) (executionsources.Config, error) {
	c, e := executionsources.DecodeConfig(public)
	if e != nil || len(c.Materials) != 0 {
		return executionsources.Config{}, ErrExecutionRuntime
	}
	c.Materials, e = executionsources.DecodeMaterials(private)
	if e != nil || c.Materials == nil {
		return executionsources.Config{}, ErrExecutionRuntime
	}
	return c, nil
}
