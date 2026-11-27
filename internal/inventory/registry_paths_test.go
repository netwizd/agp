package inventory

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestInventoryPublicFilePrivateTempDirectory(t *testing.T) {
	dir := privateTestDir(t)
	name := filepath.Join(dir, "public.json")
	if e := os.WriteFile(name, []byte("trusted public bytes"), 0644); e != nil {
		t.Fatal(e)
	}
	f, e := openPublicFile(name)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	b, e := io.ReadAll(f)
	if e != nil || string(b) != "trusted public bytes" {
		t.Fatalf("public read: %q %v", b, e)
	}
}

func TestInventoryPublicFileRejectsWritableAncestors(t *testing.T) {
	for _, mode := range []os.FileMode{0770, 0777} {
		t.Run(mode.String(), func(t *testing.T) {
			base := privateTestDir(t)
			shared := filepath.Join(base, "shared")
			if e := os.Mkdir(shared, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(shared, mode); e != nil {
				t.Fatal(e)
			}
			private := filepath.Join(shared, "private")
			if e := os.Mkdir(private, 0700); e != nil {
				t.Fatal(e)
			}
			name := filepath.Join(private, "registry.json")
			if e := os.WriteFile(name, []byte("original public trust"), 0600); e != nil {
				t.Fatal(e)
			}
			if f, e := openPublicFile(name); !errors.Is(e, ErrUnavailable) {
				if f != nil {
					_ = f.Close()
				}
				t.Fatalf("writable ancestor accepted: %v", e)
			}
			// A peer able to write shared can rename the entire protected child and
			// replace it with a same-mode tree. Final-file mode alone cannot help.
			if e := os.Rename(private, filepath.Join(shared, "original")); e != nil {
				t.Fatal(e)
			}
			if e := os.Mkdir(private, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(name, []byte("replacement trust"), 0600); e != nil {
				t.Fatal(e)
			}
			if f, e := openPublicFile(name); !errors.Is(e, ErrUnavailable) {
				if f != nil {
					_ = f.Close()
				}
				t.Fatalf("renamed replacement accepted: %v", e)
			}
		})
	}
}

func TestInventoryPublicFileRejectsSymlinksAndWritableLeaf(t *testing.T) {
	dir := privateTestDir(t)
	target := filepath.Join(dir, "real")
	if e := os.Mkdir(target, 0700); e != nil {
		t.Fatal(e)
	}
	name := filepath.Join(target, "public.json")
	if e := os.WriteFile(name, []byte("public"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	if f, e := openPublicFile(filepath.Join(link, "public.json")); e == nil {
		_ = f.Close()
		t.Fatal("ancestor symlink accepted")
	}
	leaf := filepath.Join(target, "link.json")
	if e := os.Symlink(name, leaf); e != nil {
		t.Fatal(e)
	}
	if f, e := openPublicFile(leaf); e == nil {
		_ = f.Close()
		t.Fatal("leaf symlink accepted")
	}
	if e := os.Chmod(name, 0660); e != nil {
		t.Fatal(e)
	}
	if f, e := openPublicFile(name); e == nil {
		_ = f.Close()
		t.Fatal("group-writable leaf accepted")
	}
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	// Go 1.26 uses GOTMPDIR for t.TempDir, and its numbered child inherits
	// the caller's umask. Trust fixtures require a private tree explicitly.
	t.Setenv("GOTMPDIR", "/tmp")
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return dir
}
