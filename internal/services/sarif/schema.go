// Copyright 2022 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package sarif

type Artifact struct {
	Location LocationComponent `json:"location"`
}

type LocationComponent struct {
	URI string `json:"uri"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation LocationComponent `json:"artifactLocation"`
	Region           SnippetRegion     `json:"region"`
}

type ReportRun struct {
	Tool      ScanTool   `json:"tool"`
	Artifacts []Artifact `json:"artifacts"`
	Results   []Result   `json:"results"`
}

type Report struct {
	Runs      []ReportRun `json:"runs"`
	Version   string      `json:"version"`
	SchemaURI string      `json:"$schema"`
}

type Result struct {
	Message   TextDisplayComponent `json:"message"`
	Level     ResultLevel          `json:"level"`
	Locations []Location           `json:"locations"`
	RuleID    string               `json:"ruleId"`
}

type ResultLevel string

const (
	Error   = "error"
	Warning = "warning"
	Note    = "note"
)

type Rule struct {
	ID               string               `json:"id"`
	ShortDescription TextDisplayComponent `json:"shortDescription"`
	FullDescription  TextDisplayComponent `json:"fullDescription"`
	HelpURI          string               `json:"helpUri"`
	Name             string               `json:"name"`
}

type ScanTool struct {
	Driver ScanToolDriver `json:"driver"`
}

type ScanToolDriver struct {
	Name               string `json:"name"`
	MoreInformationURI string `json:"informationUri"`
	Rules              []Rule `json:"rules"`
	Version            string `json:"version"`
}

type SnippetRegion struct {
	Snippet     TextDisplayComponent `json:"snippet"`
	StartLine   int                  `json:"startLine"`
	StartColumn int                  `json:"startColumn"`
}

type TextDisplayComponent struct {
	Text string `json:"text"`
}

type TextRange struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}
