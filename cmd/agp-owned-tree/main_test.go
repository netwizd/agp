package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/ownedtree"
)

func TestCLILocalArgumentsAndRootBoundary(t *testing.T) {
	for _, args := range [][]string{nil, {"-manifest", "/sensitive/private"}, {"-manifest", "/sensitive/private", "-ownership-digest", "bad"}, {"-unknown", "private-value"}} {
		var out bytes.Buffer
		if err := run(context.Background(), args, &out); err != errArguments || out.Len() != 0 || strings.Contains(err.Error(), "private") {
			t.Fatalf("invalid arguments disclosed output: %v %q", err, out.String())
		}
	}
	if os.Geteuid() != 0 {
		var out bytes.Buffer
		err := run(context.Background(), []string{"-manifest", "/sensitive/private", "-ownership-digest", configmodel.DigestBytes(nil)}, &out)
		if err != errRoot || out.Len() != 0 {
			t.Fatalf("nonroot inspection accepted: %v", err)
		}
	}
}

func TestCLIHelpDoesNotRequireRoot(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &out); err != nil || !strings.Contains(out.String(), "Read-only filesystem observation") {
		t.Fatalf("help unavailable: %v", err)
	}
}

func cliManifest(t *testing.T) (string, string, string) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "agp-owned-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	root := filepath.Join(base, "gateway")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("private configuration fixture\n")
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), content, 0600); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	m := ownedtree.Manifest{APIVersion: "agp.owned-tree/v1alpha1", NodeID: "node", SiteID: "site", Root: root, Entries: []ownedtree.Entry{
		{Path: ".", Kind: "directory", UID: uid, GID: gid, Mode: "0700", Size: 0, Digest: ""},
		{Path: "nginx.conf", Kind: "file", UID: uid, GID: gid, Mode: "0600", Size: ownedtree.UInt63(len(content)), Digest: configmodel.DigestBytes(content)},
	}}
	digest, err := ownedtree.Digest(m)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(base, "manifest.json")
	if err := os.WriteFile(manifest, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return manifest, digest, root
}

func TestCLIProtectedManifestObservation(t *testing.T) {
	manifest, digest, _ := cliManifest(t)
	var out bytes.Buffer
	if err := observe(context.Background(), manifest, digest, &out); err != nil {
		t.Fatal(err)
	}
	var result ownedtree.Observation
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.NoExecution || result.RuntimeValidated || result.ManifestDigest != digest || result.NodeID != "node" || result.SiteID != "site" || len(result.Entries) != 2 {
		t.Fatalf("invalid local observation: %v", err)
	}
	if bytes.Contains(out.Bytes(), []byte("private configuration fixture")) {
		t.Fatal("observation disclosed configuration bytes")
	}
}

func TestCLIDriftCancellationAndWrongPinHaveNoOutput(t *testing.T) {
	for _, change := range []string{"drift", "digest", "canceled", "manifest_symlink"} {
		t.Run(change, func(t *testing.T) {
			manifest, digest, root := cliManifest(t)
			ctx := context.Background()
			switch change {
			case "drift":
				if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte("different"), 0600); err != nil {
					t.Fatal(err)
				}
			case "digest":
				digest = configmodel.DigestBytes([]byte("other manifest"))
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "manifest_symlink":
				link := manifest + ".link"
				if err := os.Symlink(manifest, link); err != nil {
					t.Fatal(err)
				}
				manifest = link
			}
			var out bytes.Buffer
			if err := observe(ctx, manifest, digest, &out); err != errObserve || out.Len() != 0 {
				t.Fatalf("failed observation returned data: err=%v bytes=%d", err, out.Len())
			}
		})
	}
}

type shortOutput struct{}

func (shortOutput) Write([]byte) (int, error) { return 0, nil }

func TestCLIOutputFailureIsNotSuccess(t *testing.T) {
	manifest, digest, _ := cliManifest(t)
	if err := observe(context.Background(), manifest, digest, shortOutput{}); err != errObserve {
		t.Fatalf("short output reported success: %v", err)
	}
	if err := observe(context.Background(), manifest, digest, io.Discard); err != nil {
		t.Fatal(err)
	}
}
