//go:build linux

package helper

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/ownedtree"
)

func admissionOwnedTree(t *testing.T, f *admissionFixture) (*ownedtree.Tree, string) {
	t.Helper()
	root := admissionTempDir(t)
	content := []byte("events {}\nhttp {}\n")
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), content, 0600); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	m := ownedtree.Manifest{APIVersion: "agp.owned-tree/v1alpha1", NodeID: f.i.NodeID, SiteID: f.i.SiteID, Root: root, Entries: []ownedtree.Entry{
		{Path: ".", Kind: "directory", UID: uid, GID: gid, Mode: "0700", Size: 0, Digest: ""},
		{Path: "nginx.conf", Kind: "file", UID: uid, GID: gid, Mode: "0600", Size: ownedtree.UInt63(len(content)), Digest: configmodel.DigestBytes(content)},
	}}
	digest, err := ownedtree.Digest(m)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := ownedtree.Open(m, digest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tree.Close() })
	f.i.OwnershipDigest = digest
	f.r.Permit.OwnershipDigest = digest
	f.r.Permit.Recovery.OwnershipDigest = digest
	f.r.Permit.InstallationDigest, err = installationDigest(f.i)
	if err != nil {
		t.Fatal(err)
	}
	f.sign(t)
	return tree, root
}

func openOwnedAdmission(t *testing.T, f *admissionFixture, tree *ownedtree.Tree) (*Store, *Gate, string) {
	t.Helper()
	dir := admissionTempDir(t)
	s, _ := f.open(t, dir, true)
	g, err := NewGateWithOwnedTree(s, f.trust, f.sources, tree)
	if err != nil {
		t.Fatal(err)
	}
	g.now = func() time.Time { return f.sources.now }
	return s, g, dir
}

func TestAdmissionOwnedTreeBinding(t *testing.T) {
	for _, change := range []string{"node", "site", "manifest", "nil_tree", "nil_store"} {
		t.Run(change, func(t *testing.T) {
			f := newAdmissionFixture(t)
			tree, _ := admissionOwnedTree(t, f)
			s, _ := f.open(t, admissionTempDir(t), true)
			switch change {
			case "node":
				s.installation.NodeID = "different-node"
			case "site":
				s.installation.SiteID = "different-site"
			case "manifest":
				s.installation.OwnershipDigest = testDigest("other-manifest")
			case "nil_tree":
				tree = nil
			case "nil_store":
				s = nil
			}
			if g, err := NewGateWithOwnedTree(s, f.trust, f.sources, tree); g != nil || err != ErrInvalid {
				t.Fatalf("unbound verifier accepted: gate=%v err=%v", g != nil, err)
			}
		})
	}
}

func TestAdmissionOwnedTreeDriftDoesNotConsumeSequence(t *testing.T) {
	for _, change := range []string{"content", "extra_file", "removed_file", "mode", "closed_verifier"} {
		t.Run(change, func(t *testing.T) {
			f := newAdmissionFixture(t)
			tree, root := admissionOwnedTree(t, f)
			s, g, dir := openOwnedAdmission(t, f, tree)
			before, err := os.ReadFile(filepath.Join(dir, storeStateName))
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "content":
				err = os.WriteFile(filepath.Join(root, "nginx.conf"), []byte("changed bytes\n"), 0600)
			case "extra_file":
				err = os.WriteFile(filepath.Join(root, ".unexpected"), []byte("extra"), 0600)
			case "removed_file":
				err = os.Remove(filepath.Join(root, "nginx.conf"))
			case "mode":
				err = os.Chmod(filepath.Join(root, "nginx.conf"), 0644)
			case "closed_verifier":
				err = tree.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r)))
			if out != nil || err != ErrOwnedTree || f.sources.starts != 0 || f.sources.heads != 0 {
				t.Fatalf("drift was admitted/contacted authority: receipt=%v err=%v heads=%d starts=%d", out, err, f.sources.heads, f.sources.starts)
			}
			after, err := os.ReadFile(filepath.Join(dir, storeStateName))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejection changed durable state: %v", err)
			}
			status, err := s.Status(context.Background())
			if err != nil || status.HighWater != f.i.Baseline.NodeDeploymentSequence || status.Admission != nil {
				t.Fatalf("drift consumed sequence: %#v %v", status, err)
			}
		})
	}
}

func TestAdmissionOwnedTreeRechecksAfterAuthorization(t *testing.T) {
	f := newAdmissionFixture(t)
	tree, root := admissionOwnedTree(t, f)
	s, g, _ := openOwnedAdmission(t, f, tree)
	f.sources.afterProof = func() {
		if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte("unapproved tree\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r)))
	if out != nil || err != ErrOwnedTree || f.sources.starts != 1 || f.sources.heads != 2 {
		t.Fatalf("post-authorization drift accepted: %#v %v heads=%d starts=%d", out, err, f.sources.heads, f.sources.starts)
	}
	status, err := s.Status(context.Background())
	if err != nil || status.HighWater != f.i.Baseline.NodeDeploymentSequence || status.Admission != nil {
		t.Fatalf("rejected late drift consumed sequence: %#v %v", status, err)
	}
}

func TestAdmissionOwnedTreeHistoricalReplayWithoutFilesystem(t *testing.T) {
	f := newAdmissionFixture(t)
	tree, _ := admissionOwnedTree(t, f)
	s, g, dir := openOwnedAdmission(t, f, tree)
	raw := testBytes(t, f.r)
	first, err := g.Admit(context.Background(), bytes.NewReader(raw))
	if err != nil || first == nil || !first.NoExecution {
		t.Fatalf("first admission: %#v %v", first, err)
	}
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	f.sources.now = f.sources.now.Add(24 * time.Hour)
	f.sources.offline = true
	s, _ = f.open(t, dir, false)
	g, err = NewGateWithOwnedTree(s, f.trust, f.sources, tree)
	if err != nil {
		t.Fatal(err)
	}
	g.now = func() time.Time { return f.sources.now }
	replay, err := g.Admit(context.Background(), bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(first, replay) || f.sources.heads != 2 || f.sources.starts != 1 {
		t.Fatalf("historical replay required fresh tree/network: %#v %v", replay, err)
	}
	f.r.Task.ID = "later-task"
	f.r.Task.IdempotencyKey = "later-idempotency-key"
	f.sign(t)
	if out, err := g.Admit(context.Background(), bytes.NewReader(testBytes(t, f.r))); out != nil || err != ErrPending {
		t.Fatalf("old receipt cleared blocker: %#v %v", out, err)
	}
}
