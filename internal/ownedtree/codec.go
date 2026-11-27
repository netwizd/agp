package ownedtree

import (
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/netwizd/agp/internal/configmodel"
)

// A closed wire DTO uses int for UID/GID because the shared strict decoder
// intentionally supports exact JSON integer tokens rather than arbitrary Go
// unsigned kinds. Conversion is checked before populating the public uint32s.
type wireEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Mode   string `json:"mode"`
	Size   UInt63 `json:"size"`
	Digest string `json:"digest"`
}
type wireManifest struct {
	APIVersion string      `json:"apiVersion"`
	NodeID     string      `json:"nodeId"`
	SiteID     string      `json:"siteId"`
	Root       string      `json:"root"`
	Entries    []wireEntry `json:"entries"`
}

func Parse(r io.Reader) (*Manifest, error) {
	if r == nil {
		return nil, ErrManifest
	}
	var w wireManifest
	if configmodel.StrictJSON(r, &w, MaxManifestBytes) != nil {
		return nil, ErrManifest
	}
	m := Manifest{APIVersion: w.APIVersion, NodeID: w.NodeID, SiteID: w.SiteID, Root: w.Root, Entries: make([]Entry, len(w.Entries))}
	for i, e := range w.Entries {
		if e.UID < 0 || uint64(e.UID) > 1<<32-1 || e.GID < 0 || uint64(e.GID) > 1<<32-1 {
			return nil, ErrManifest
		}
		m.Entries[i] = Entry{Path: e.Path, Kind: e.Kind, UID: uint32(e.UID), GID: uint32(e.GID), Mode: e.Mode, Size: e.Size, Digest: e.Digest}
	}
	return Normalize(m)
}

// Normalize returns detached, path-sorted metadata, with explicit parent
// closure. It does not inspect the filesystem or grant ownership authority.
func Normalize(m Manifest) (*Manifest, error) {
	if m.APIVersion != Version || !configmodel.ValidID(m.NodeID) || !configmodel.ValidID(m.SiteID) || !validRoot(m.Root) || len(m.Entries) < 1 || len(m.Entries) > MaxEntries {
		return nil, ErrManifest
	}
	m.Entries = append([]Entry(nil), m.Entries...)
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Path < m.Entries[j].Path })
	parents := make(map[string]string, len(m.Entries))
	for _, e := range m.Entries {
		if _, exists := parents[e.Path]; exists {
			return nil, ErrManifest
		}
		parents[e.Path] = e.Kind
	}
	var total uint64
	for _, e := range m.Entries {
		if !validRelative(e.Path) {
			return nil, ErrManifest
		}
		mode, err := entryMode(e.Mode)
		if err != nil || mode&0022 != 0 {
			return nil, ErrManifest
		}
		switch e.Kind {
		case "directory":
			if e.Size != 0 || e.Digest != "" {
				return nil, ErrManifest
			}
		case "file":
			if mode&0111 != 0 || e.Size > MaxFileBytes || !configmodel.ValidDigest(e.Digest) {
				return nil, ErrManifest
			}
			total += uint64(e.Size)
			if total > MaxTotalBytes {
				return nil, ErrManifest
			}
		default:
			return nil, ErrManifest
		}
		if e.Path == "." {
			if e.Kind != "directory" {
				return nil, ErrManifest
			}
		} else if parents[path.Dir(e.Path)] != "directory" {
			return nil, ErrManifest
		}
	}
	if parents["."] != "directory" {
		return nil, ErrManifest
	}
	b, err := configmodel.CanonicalJSON(m)
	if err != nil || len(b) > MaxManifestBytes {
		return nil, ErrManifest
	}
	return &m, nil
}

func Digest(m Manifest) (string, error) {
	n, err := Normalize(m)
	if err != nil {
		return "", err
	}
	d, err := configmodel.Digest(n)
	if err != nil {
		return "", ErrManifest
	}
	return d, nil
}

func entryMode(s string) (uint32, error) {
	if len(s) != 4 || s[0] != '0' {
		return 0, ErrManifest
	}
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, ErrManifest
		}
	}
	n, err := strconv.ParseUint(s, 8, 12)
	if err != nil {
		return 0, ErrManifest
	}
	return uint32(n), nil
}
func validRoot(s string) bool {
	if len(s) < 2 || len(s) > MaxPathBytes || s[0] != '/' || path.Clean(s) != s {
		return false
	}
	return asciiPath(s) && len(strings.Split(strings.TrimPrefix(s, "/"), "/")) <= MaxPathBytes/2
}
func validRelative(s string) bool {
	if s == "." {
		return true
	}
	if s == "" || len(s) > MaxPathBytes || strings.HasPrefix(s, "/") || path.Clean(s) != s || !asciiPath(s) || len(strings.Split(s, "/")) > MaxDepth {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "." || p == ".." || p == "" {
			return false
		}
	}
	return true
}
func asciiPath(s string) bool {
	for _, c := range s {
		if c < 0x21 || c > 0x7e || c == '\\' {
			return false
		}
	}
	return true
}
