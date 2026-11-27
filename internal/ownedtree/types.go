// Package ownedtree observes an explicitly enumerated, protected configuration
// tree. It never follows links, executes a program, modifies a file, or proves
// that the observed files are the active configuration of a running process.
package ownedtree

import (
	"errors"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
)

const (
	Version            = "agp.owned-tree/v1alpha1"
	ObservationVersion = "agp.owned-tree-observation/v1alpha1"
	MaxManifestBytes   = 1 << 20
	MaxEntries         = 4096
	MaxDepth           = 16
	MaxPathBytes       = 1024
	MaxFileBytes       = 4 << 20
	MaxTotalBytes      = 64 << 20
)

type UInt63 = securityjournal.UInt63

var (
	ErrManifest    = errors.New("owned_tree_manifest_invalid")
	ErrTree        = errors.New("owned_tree_verification_failed")
	ErrClosed      = errors.New("owned_tree_closed")
	ErrUnsupported = errors.New("owned_tree_mount_proof_unavailable")
)

type Manifest struct {
	APIVersion string  `json:"apiVersion"`
	NodeID     string  `json:"nodeId"`
	SiteID     string  `json:"siteId"`
	Root       string  `json:"root"`
	Entries    []Entry `json:"entries"`
}

type Entry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   string `json:"mode"`
	Size   UInt63 `json:"size"`
	Digest string `json:"digest"`
}

type Binding struct {
	NodeID         string `json:"nodeId"`
	SiteID         string `json:"siteId"`
	ManifestDigest string `json:"manifestDigest"`
}

type ObservedEntry struct {
	Entry
	Device     UInt63 `json:"device"`
	Inode      UInt63 `json:"inode"`
	MountID    UInt63 `json:"mountId"`
	Links      UInt63 `json:"links"`
	ModifiedAt string `json:"modifiedAt"`
	ChangedAt  string `json:"changedAt"`
}

// Observation describes bytes and metadata seen through pinned descriptors.
// Its timestamp uses the local clock, not the independent security authority.
// It confers no permission to execute, apply, reload, or capture a baseline.
type Observation struct {
	APIVersion       string          `json:"apiVersion"`
	Purpose          string          `json:"purpose"`
	NoExecution      bool            `json:"noExecution"`
	RuntimeValidated bool            `json:"runtimeValidated"`
	NodeID           string          `json:"nodeId"`
	SiteID           string          `json:"siteId"`
	ManifestDigest   string          `json:"manifestDigest"`
	TreeDigest       string          `json:"treeDigest"`
	Root             string          `json:"root"`
	ObservedAt       time.Time       `json:"observedAt"`
	Entries          []ObservedEntry `json:"entries"`
}
