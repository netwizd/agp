package repository

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type trustConfig struct {
	Root             json.RawMessage   `json:"root"`
	ReleaseKeys      map[string]string `json:"releaseKeys"`
	ReleaseThreshold int               `json:"releaseThreshold"`
	Platform         Platform          `json:"platform"`
	MinimumSequence  string            `json:"minimumSequence"`
	SecurityFloor    string            `json:"securityFloor"`
}

// ReadAnchor reads only public trust material from an installation-owned file.
// It is deliberately separate from bundle input and refreshed on each use so
// release-key revocation is not hidden by an old process cache.
func ReadAnchor(file string) (Anchor, error) {
	var out Anchor
	b, e := readRegular(file, MaxMetadataBytes)
	if e != nil {
		return out, e
	}
	var c trustConfig
	if e = strict(b, &c); e != nil {
		return out, e
	}
	out.Root, out.Platform, out.ReleaseThreshold = c.Root, c.Platform, c.ReleaseThreshold
	out.MinimumSequence, e = decimal(c.MinimumSequence)
	if e != nil {
		return out, e
	}
	out.SecurityFloor, e = decimal(c.SecurityFloor)
	if e != nil {
		return out, e
	}
	out.ReleaseKeys = map[string]ed25519.PublicKey{}
	for id, raw := range c.ReleaseKeys {
		key, err := base64.StdEncoding.Strict().DecodeString(raw)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return out, reject("release public key")
		}
		out.ReleaseKeys[id] = ed25519.PublicKey(key)
	}
	return out, nil
}
func readRegular(file string, maxBytes int64) ([]byte, error) {
	fd, e := unix.Open(file, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), file)
	defer f.Close()
	return readFile(f, maxBytes)
}
func readFile(f *os.File, maxBytes int64) ([]byte, error) {
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > maxBytes {
		return nil, reject("file type or byte limit")
	}
	b, e := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if e != nil || int64(len(b)) != st.Size() || int64(len(b)) > maxBytes {
		return nil, reject("file read size changed")
	}
	return b, nil
}

// DirectoryReader never follows bundle symlinks, including parent components.
// It reads regular files only; it does not extract or execute archive members.
func DirectoryReader(root string) func(string, int64) ([]byte, error) {
	return func(relative string, maxBytes int64) ([]byte, error) {
		if !validPath(relative) {
			return nil, reject("bundle path")
		}
		dir, e := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		parts := strings.Split(relative, "/")
		for _, component := range parts[:len(parts)-1] {
			next, err := unix.Openat(dir, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			unix.Close(dir)
			if err != nil {
				return nil, err
			}
			dir = next
		}
		fd, e := unix.Openat(dir, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dir)
		if e != nil {
			return nil, e
		}
		f := os.NewFile(uintptr(fd), relative)
		defer f.Close()
		return readFile(f, maxBytes)
	}
}

type bundleIndex struct {
	ManifestPath string  `json:"manifestPath"`
	RootVersions []int64 `json:"rootVersions"`
}

func ReadBundle(dir string) (Input, error) {
	read := DirectoryReader(dir)
	var out Input
	b, e := read("bundle.json", 8192)
	if e != nil {
		return out, e
	}
	var index bundleIndex
	if e = strict(b, &index); e != nil {
		return out, e
	}
	if !manifestPattern.MatchString(index.ManifestPath) || len(index.RootVersions) > 32 {
		return out, reject("bundle index")
	}
	out.ManifestPath = index.ManifestPath
	for _, version := range index.RootVersions {
		if version < 1 {
			return out, reject("root version")
		}
		b, e = read("metadata/"+strconv.FormatInt(version, 10)+".root.json", MaxMetadataBytes)
		if e != nil {
			return out, e
		}
		out.RootUpdates = append(out.RootUpdates, b)
	}
	for name, target := range map[string]*[]byte{"timestamp": &out.Timestamp, "snapshot": &out.Snapshot, "targets": &out.Targets} {
		*target, e = read("metadata/"+name+".json", MaxMetadataBytes)
		if e != nil {
			return out, e
		}
	}
	out.Manifest, e = read(index.ManifestPath, MaxMetadataBytes)
	if e != nil {
		return out, e
	}
	out.ReadObject = read
	return out, nil
}

type storeRecord struct {
	State        State           `json:"state"`
	ManifestPath string          `json:"manifestPath"`
	Manifest     json.RawMessage `json:"manifest"`
}
type Store struct{ Dir, AnchorPath string }

func (s Store) record() (*storeRecord, error) {
	b, e := DirectoryReader(s.Dir)("state.json", 24<<20)
	if e != nil {
		return nil, e
	}
	var record storeRecord
	// This installation-owned record can contain several bounded metadata files.
	// Its nested metadata is independently authenticated by Verify on every use.
	if e = json.Unmarshal(b, &record); e != nil {
		return nil, reject("trust store state")
	}
	return &record, nil
}

// Current requires fresh independently verified time, not a CP wall clock or
// an HTTP parameter. The production provider uses the independent journal's
// challenge-bound signed head. This read does not advance a clock highwater.
func (s Store) Current(ctx context.Context, now time.Time) (*VerifiedRelease, error) {
	a, e := ReadAnchor(s.AnchorPath)
	if e != nil {
		return nil, e
	}
	r, e := s.record()
	if e != nil {
		return nil, e
	}
	in := Input{Timestamp: r.State.Timestamp, Snapshot: r.State.Snapshot, Targets: r.State.Targets, ManifestPath: r.ManifestPath, Manifest: r.Manifest, ReadObject: DirectoryReader(s.Dir)}
	return Verify(ctx, a, &r.State, in, now)
}

// Import is an offline administrative operation. The CP only uses Current;
// it does not create anchors, sign releases, import files or advance this store.
// All durable files remain outside CP database backup/restore.
func (s Store) Import(ctx context.Context, bundleDir string, now time.Time) (*VerifiedRelease, error) {
	st, e := os.Lstat(s.Dir)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
		return nil, reject("private independent trust directory required")
	}
	lock, e := os.OpenFile(filepath.Join(s.Dir, "import.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return nil, reject("another trust import is active")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	a, e := ReadAnchor(s.AnchorPath)
	if e != nil {
		return nil, e
	}
	var previous *State
	old, e := s.record()
	if e == nil {
		previous = &old.State
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	in, e := ReadBundle(bundleDir)
	if e != nil {
		return nil, e
	}
	v, e := Verify(ctx, a, previous, in, now)
	if e != nil {
		return nil, e
	}
	if _, e = v.QualifiedProfile(now); e != nil {
		return nil, e
	}
	objectsDir := filepath.Join(s.Dir, "objects")
	if e = os.Mkdir(objectsDir, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return nil, e
	}
	objectInfo, e := os.Lstat(objectsDir)
	if e != nil || !objectInfo.IsDir() || objectInfo.Mode()&os.ModeSymlink != 0 {
		return nil, reject("CAS directory")
	}
	for digest, raw := range v.objects {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		name := strings.TrimPrefix(digest, "sha256:")
		destination := filepath.Join(objectsDir, name)
		f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
		if errors.Is(err, os.ErrExist) {
			b, err := DirectoryReader(s.Dir)("objects/"+name, int64(len(raw)))
			if err != nil || Hash(b) != digest {
				return nil, reject("existing CAS object integrity")
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return nil, fmt.Errorf("CAS durable write: %w", errors.Join(err, closeErr))
		}
	}
	if e = syncDir(objectsDir); e != nil {
		return nil, e
	}
	// Rename one record containing both metadata highwater and current manifest.
	// A crash before rename leaves only harmless unreferenced CAS objects.
	data, e := json.Marshal(storeRecord{State: v.Next, ManifestPath: in.ManifestPath, Manifest: in.Manifest})
	if e != nil {
		return nil, e
	}
	f, e := os.CreateTemp(s.Dir, ".state-")
	if e != nil {
		return nil, e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return nil, errors.Join(e, closeErr)
	}
	if e = os.Rename(f.Name(), filepath.Join(s.Dir, "state.json")); e != nil {
		return nil, e
	}
	if e = syncDir(s.Dir); e != nil {
		return nil, e
	}
	return v, nil
}
func syncDir(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
