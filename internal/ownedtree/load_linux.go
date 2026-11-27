//go:build linux

package ownedtree

import (
	"bytes"
	"io"
	"path"

	"github.com/netwizd/agp/internal/configmodel"
	"golang.org/x/sys/unix"
)

// Load reads an existing protected manifest and opens its owned tree. The
// expected digest must come from a separate trusted installation source; a
// manifest cannot approve itself. Loading grants no baseline or runtime claim.
func Load(manifestPath, expectedDigest string) (*Tree, error) {
	if !validRoot(manifestPath) || !configmodel.ValidDigest(expectedDigest) {
		return nil, ErrManifest
	}
	parent := path.Dir(manifestPath)
	if parent == "/" {
		return nil, ErrManifest
	}
	anchors, err := openAncestry(parent, mountID)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := len(anchors) - 1; i >= 0; i-- {
			_ = anchors[i].file.Close()
		}
	}()
	last := anchors[len(anchors)-1]
	fd, err := unix.Openat(int(last.file.Fd()), path.Base(manifestPath), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrManifest
	}
	p, err := makePin(fd, path.Base(manifestPath), len(anchors)-1, mountID)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	defer p.file.Close()
	st := p.stat
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || !trustedUID(st.Uid) || st.Mode&07133 != 0 || st.Size < 1 || st.Size > MaxManifestBytes {
		return nil, ErrManifest
	}
	if checkName(last, p, true) != nil {
		return nil, ErrManifest
	}
	b, err := io.ReadAll(io.LimitReader(p.file, MaxManifestBytes+1))
	if err != nil || int64(len(b)) != st.Size || len(b) > MaxManifestBytes {
		return nil, ErrManifest
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || !sameFull(st, after) || checkName(last, p, true) != nil || checkAncestry(anchors, mountID) != nil {
		return nil, ErrManifest
	}
	m, err := Parse(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	t, err := Open(*m, expectedDigest)
	if err != nil {
		return nil, err
	}
	if unix.Fstat(fd, &after) != nil || !sameFull(st, after) || checkName(last, p, true) != nil || checkAncestry(anchors, mountID) != nil {
		_ = t.Close()
		return nil, ErrManifest
	}
	return t, nil
}
