// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package sonarqube

type Report struct {
	Issues []Issue `json:"issues"`
}

type Issue struct {
	Type               string     `json:"type"`
	RuleID             string     `json:"ruleId"`
	EngineID           string     `json:"engineId"`
	Severity           string     `json:"severity"`
	EffortMinutes      int        `json:"effortMinutes"`
	PrimaryLocation    Location   `json:"primaryLocation"`
	SecondaryLocations []Location `json:"secondaryLocations,omitempty"`
}

type Location struct {
	Message  string    `json:"message"`
	Filepath string    `json:"filePath"`
	Range    TextRange `json:"textRange"`
}

type TextRange struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}
