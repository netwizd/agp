package ownedtree

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
)

func sampleManifest() Manifest {
	return Manifest{APIVersion: Version, NodeID: "node-1", SiteID: "site-1", Root: "/etc/agp/versions/initial", Entries: []Entry{
		{Path: ".", Kind: "directory", Mode: "0700", Size: 0},
		{Path: "nginx.conf", Kind: "file", Mode: "0600", Size: 4, Digest: configmodel.DigestBytes([]byte("test"))},
	}}
}

func TestManifestClosedWire(t *testing.T) {
	m := sampleManifest()
	raw, _ := json.Marshal(m)
	if _, err := Parse(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(string) string{
		"unknown":      func(s string) string { return strings.Replace(s, `"siteId":`, `"baseline":false,"siteId":`, 1) },
		"case":         func(s string) string { return strings.Replace(s, `"nodeId"`, `"NodeId"`, 1) },
		"missing":      func(s string) string { return strings.Replace(s, `"uid":0,`, ``, 1) },
		"duplicate":    func(s string) string { return strings.Replace(s, `"uid":0`, `"uid":0,"uid":0`, 1) },
		"null":         func(s string) string { return strings.Replace(s, `"digest":""`, `"digest":null`, 1) },
		"number-size":  func(s string) string { return strings.Replace(s, `"size":"0"`, `"size":0`, 1) },
		"leading-zero": func(s string) string { return strings.Replace(s, `"size":"0"`, `"size":"00"`, 1) },
		"negative-uid": func(s string) string { return strings.Replace(s, `"uid":0`, `"uid":-1`, 1) },
		"overflow-gid": func(s string) string { return strings.Replace(s, `"gid":0`, `"gid":4294967296`, 1) },
		"fraction":     func(s string) string { return strings.Replace(s, `"uid":0`, `"uid":0.0`, 1) },
		"trailing":     func(s string) string { return s + ` {}` },
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Parse(strings.NewReader(change(string(raw)))); err == nil || got != nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
	if _, err := Parse(strings.NewReader(strings.Repeat(" ", MaxManifestBytes+1))); err == nil {
		t.Fatal("oversized accepted")
	}
}

func TestManifestNormalizationAndBounds(t *testing.T) {
	m := sampleManifest()
	m.Entries = append(m.Entries, Entry{Path: "!first", Kind: "file", Mode: "0400", Digest: configmodel.DigestBytes(nil)})
	n, err := Normalize(m)
	if err != nil {
		t.Fatal(err)
	}
	if n.Entries[0].Path != "!first" {
		t.Fatal("not lexicographically sorted")
	}
	n.Entries[0].Path = "changed"
	if m.Entries[2].Path != "!first" {
		t.Fatal("aliased input")
	}
	a, _ := Digest(m)
	m.Entries[0], m.Entries[2] = m.Entries[2], m.Entries[0]
	b, _ := Digest(m)
	if a != b {
		t.Fatal("order changed digest")
	}
	for name, change := range map[string]func(*Manifest){
		"version":         func(m *Manifest) { m.APIVersion = "other" },
		"root-relative":   func(m *Manifest) { m.Root = "etc/agp" },
		"root-unclean":    func(m *Manifest) { m.Root = "/etc/../agp" },
		"root-system":     func(m *Manifest) { m.Root = "/" },
		"path-escape":     func(m *Manifest) { m.Entries[1].Path = "../outside" },
		"path-absolute":   func(m *Manifest) { m.Entries[1].Path = "/outside" },
		"path-unicode":    func(m *Manifest) { m.Entries[1].Path = "конфиг" },
		"path-control":    func(m *Manifest) { m.Entries[1].Path = "a\nb" },
		"path-backslash":  func(m *Manifest) { m.Entries[1].Path = "a\\b" },
		"missing-parent":  func(m *Manifest) { m.Entries[1].Path = "a/nginx.conf" },
		"missing-root":    func(m *Manifest) { m.Entries = m.Entries[1:] },
		"duplicate":       func(m *Manifest) { m.Entries = append(m.Entries, m.Entries[0]) },
		"executable-file": func(m *Manifest) { m.Entries[1].Mode = "0700" },
		"writable-group":  func(m *Manifest) { m.Entries[1].Mode = "0620" },
		"setuid":          func(m *Manifest) { m.Entries[1].Mode = "4600" },
		"kind":            func(m *Manifest) { m.Entries[1].Kind = "symlink" },
		"directory-hash":  func(m *Manifest) { m.Entries[0].Digest = configmodel.DigestBytes(nil) },
		"directory-size":  func(m *Manifest) { m.Entries[0].Size = 1 },
		"file-size":       func(m *Manifest) { m.Entries[1].Size = MaxFileBytes + 1 },
		"digest":          func(m *Manifest) { m.Entries[1].Digest = "sha256:bad" },
		"depth":           func(m *Manifest) { m.Entries[1].Path = strings.Repeat("a/", MaxDepth) + "a" },
		"path-length":     func(m *Manifest) { m.Entries[1].Path = strings.Repeat("a", MaxPathBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			v := sampleManifest()
			change(&v)
			if n, err := Normalize(v); err == nil || n != nil {
				t.Fatal("accepted")
			}
		})
	}
	tooMany := sampleManifest()
	for i := 0; i < MaxEntries; i++ {
		tooMany.Entries = append(tooMany.Entries, Entry{Path: fmt.Sprintf("f-%04d", i), Kind: "file", Mode: "0400", Digest: configmodel.DigestBytes(nil)})
	}
	if _, err := Normalize(tooMany); err == nil {
		t.Fatal("entry budget accepted")
	}
	tooBig := sampleManifest()
	tooBig.Entries = tooBig.Entries[:1]
	for i := 0; i < 17; i++ {
		tooBig.Entries = append(tooBig.Entries, Entry{Path: fmt.Sprintf("f-%d", i), Kind: "file", Mode: "0400", Size: MaxFileBytes, Digest: configmodel.DigestBytes(nil)})
	}
	if _, err := Normalize(tooBig); err == nil {
		t.Fatal("total byte budget accepted")
	}
}
