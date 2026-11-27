//go:build linux

package nativeactivation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/netwizd/agp/internal/configmodel"
	"golang.org/x/sys/unix"
)

func checkRuntimeTree(ctx context.Context, c Config, owner uint32) error {
	if len(c.RuntimeEntries) < 3 || len(c.RuntimeEntries) > 4096 {
		return ErrInstallation
	}
	root, e := openDir(c.RuntimeDir, owner)
	if e != nil {
		return e
	}
	defer root.close()
	entries := append([]RuntimeEntry(nil), c.RuntimeEntries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	files := map[string]*os.File{".": root.file()}
	defer func() {
		for p, f := range files {
			if p != "." {
				f.Close()
			}
		}
	}()
	children := map[string][]string{}
	seen := map[string]bool{}
	var total int64
	for _, entry := range entries {
		if e = ctx.Err(); e != nil {
			return e
		}
		if seen[entry.Path] || (entry.Path != "." && !validRelative(entry.Path)) || entry.Mode < 0 || entry.Mode > 0777 || entry.Mode&0022 != 0 {
			return ErrInstallation
		}
		seen[entry.Path] = true
		var f *os.File
		if entry.Path == "." {
			if entry.Kind != "directory" || entry.Mode != 0700 {
				return ErrInstallation
			}
			f = root.file()
		} else {
			parent := files[filepath.Dir(entry.Path)]
			if parent == nil {
				return ErrInstallation
			}
			f, e = openChild(parent, filepath.Base(entry.Path), entry.Kind == "directory", owner)
			if e != nil {
				return e
			}
			files[entry.Path] = f
			children[filepath.Dir(entry.Path)] = append(children[filepath.Dir(entry.Path)], filepath.Base(entry.Path))
		}
		var before, after, named unix.Stat_t
		if unix.Fstat(int(f.Fd()), &before) != nil || int(before.Mode&07777) != entry.Mode {
			return ErrTree
		}
		switch entry.Kind {
		case "directory":
			if entry.Size != 0 || entry.Digest != "" || before.Mode&unix.S_IFMT != unix.S_IFDIR {
				return ErrInstallation
			}
		case "file":
			if entry.Size < 1 || entry.Size > 64<<20 || before.Size != int64(entry.Size) || !configmodel.ValidDigest(entry.Digest) || before.Nlink != 1 {
				return ErrInstallation
			}
			total += before.Size
			if total > 256<<20 {
				return ErrInstallation
			}
			h := sha256.New()
			n, he := io.Copy(h, io.LimitReader(f, (64<<20)+1))
			if he != nil || n != before.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != entry.Digest {
				return ErrTree
			}
		default:
			return ErrInstallation
		}
		if unix.Fstat(int(f.Fd()), &after) != nil || !fullSame(before, after) {
			return ErrTree
		}
		if entry.Path != "." {
			if unix.Fstatat(int(files[filepath.Dir(entry.Path)].Fd()), filepath.Base(entry.Path), &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !fullSame(before, named) {
				return ErrTree
			}
		}
	}
	if !seen["."] || !seen["bin/nginx"] || !seen["lib/ld-linux-x86-64.so.2"] {
		return ErrInstallation
	}
	for _, entry := range entries {
		if entry.Kind == "directory" && exactNames(files[entry.Path], children[entry.Path]) != nil {
			return ErrTree
		}
	}
	return root.check()
}
