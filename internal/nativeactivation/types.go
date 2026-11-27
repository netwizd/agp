// Package nativeactivation implements the installation-selected local filesystem
// and Nginx runtime adapter for helper.ExecutionDriver. It does not admit tasks,
// choose releases, install packages or start services.
package nativeactivation

import (
	"errors"

	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/nativesandbox"
)

const (
	// v1alpha2 separates immutable content identity from the execution sequence.
	// Earlier prototype manifests are rejected rather than silently reinterpreted.
	Version           = "agp.native-generation/v1alpha2"
	RepositoryVersion = "agp.qualified-native-repository/v1alpha1"
	BundleVersion     = "agp.qualified-native-bundle/v1alpha1"
	maxMetadata       = 1 << 20
	maxBundles        = 256
	maxBundleBytes    = 96 << 20
)

var (
	ErrInstallation = errors.New("native_activation_installation_rejected")
	ErrTree         = errors.New("native_activation_tree_changed")
	ErrBundle       = errors.New("native_activation_qualified_bundle_required")
	ErrRuntime      = errors.New("native_activation_runtime_unverified")
	ErrStale        = errors.New("native_activation_precondition_changed")
)

// Config is protected installer input, never decoded from a task. LayoutDigest
// is its separately pinned stable-layout digest; generation content has its own
// digest. A qualified bundle binds its immutable runtime content marker before
// signing. Each execution sequence selects a distinct durable storage slot.
type Config struct {
	RootDir, RuntimeDir, PIDFile, Executable, ExecutableDigest               string
	NodeID, SiteID, LayoutDigest, QualificationDigest, ReleaseManifestDigest string
	ProbeSocket                                                              string
	SandboxTool                                                              nativesandbox.Tool
	ExecutionUID, ExecutionGID                                               uint32
	RuntimeEntries                                                           []RuntimeEntry
	CgroupDir                                                                string
	CgroupMountID, CgroupInode                                               uint64
}

// RuntimeEntry pins the complete qualified loader/library/Nginx runtime.
type RuntimeEntry struct {
	Path   string
	Kind   string
	Mode   int
	Size   int
	Digest string
}

// File is a complete materialized native input, including nginx.conf and any
// required certificates. No filesystem path or artifact content comes from Task.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Digest  string `json:"digest"`
}

// Probe expectations are part of the qualified bundle, not caller assertions.
// Every response must also reflect a fresh challenge and the exact generation.
// Kind distinguishes the required route, authentication and WAF observations.
type Probe struct {
	Kind       string `json:"kind"`
	Path       string `json:"path"`
	Host       string `json:"host"`
	Status     int    `json:"status"`
	BodyDigest string `json:"bodyDigest"`
}

type Bundle struct {
	APIVersion            string  `json:"apiVersion"`
	NodeID                string  `json:"nodeId"`
	RevisionID            string  `json:"revisionId"`
	GenerationID          string  `json:"generationId"`
	BundleDigest          string  `json:"bundleDigest"`
	QualificationDigest   string  `json:"qualificationDigest"`
	ReleaseManifestDigest string  `json:"releaseManifestDigest"`
	Files                 []File  `json:"files"`
	Probes                []Probe `json:"probes"`
}

type BundlePin struct {
	BundleDigest   string `json:"bundleDigest"`
	ManifestDigest string `json:"manifestDigest"`
}

type RepositoryManifest struct {
	APIVersion string      `json:"apiVersion"`
	Bundles    []BundlePin `json:"bundles"`
}

type generationManifest struct {
	APIVersion string                     `json:"apiVersion"`
	Generation helper.ExecutionGeneration `json:"generation"`
	Entries    []generationEntry          `json:"entries"`
	Probes     []Probe                    `json:"probes"`
}

type generationEntry struct {
	Path   string        `json:"path"`
	Kind   string        `json:"kind"`
	UID    int           `json:"uid"`
	GID    int           `json:"gid"`
	Mode   string        `json:"mode"`
	Size   helper.UInt63 `json:"size"`
	Digest string        `json:"digest"`
}

type recoveryRecord struct {
	APIVersion string                     `json:"apiVersion"`
	Base       helper.ExecutionGeneration `json:"base"`
	Target     helper.ExecutionGeneration `json:"target"`
}
