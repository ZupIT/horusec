package entities

import (
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Report struct {
	SchemaVersion int                 `json:",omitempty"`
	ArtifactName  string              `json:",omitempty"`
	ArtifactType  ftypes.ArtifactType `json:",omitempty"`
	Metadata      Metadata            `json:",omitempty"`
	Results       Results             `json:",omitempty"`
}

// Metadata represents a metadata of artifact
type Metadata struct {
	Size int64      `json:",omitempty"`
	OS   *ftypes.OS `json:",omitempty"`

	// Container image
	RepoTags    []string `json:",omitempty"`
	RepoDigests []string `json:",omitempty"`
}

// Results to hold list of Result
type Results []*Result

type ResultClass string

// Result holds a target and detected vulnerabilities
type Result struct {
	Target            string                            `json:"Target"`
	Class             ResultClass                       `json:"Class,omitempty"`
	Type              string                            `json:"Type,omitempty"`
	Packages          []ftypes.Package                  `json:"Packages,omitempty"`
	Vulnerabilities   []*types.DetectedVulnerability    `json:"Vulnerabilities,omitempty"`
	MisconfSummary    *MisconfSummary                   `json:"MisconfSummary,omitempty"`
	Misconfigurations []*types.DetectedMisconfiguration `json:"Misconfigurations,omitempty"`
}

type MisconfSummary struct {
	Successes  int
	Failures   int
	Exceptions int
}
