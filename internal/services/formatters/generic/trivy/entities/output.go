// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
