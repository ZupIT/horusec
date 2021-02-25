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

package entities

import (
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/csharp/scs/severities"
)

type ScsResult struct {
	Filename      string `json:"Filename"`
	IssueSeverity string `json:"IssueSeverity"`
	ErrorID       string `json:"ErrorID"`
	IssueText     string `json:"IssueText"`
}

func (s *ScsResult) IsValid() bool {
	return !s.IsEmpty() && s.IsSecurityIssue()
}

func (s *ScsResult) IsEmpty() bool {
	return s.Filename == "" || s.IssueSeverity == "" || s.ErrorID == "" || s.IssueText == ""
}

func (s *ScsResult) IsSecurityIssue() bool {
	if s.ErrorID == "" {
		return false
	}

	return s.ErrorID[0:2] == "SC"
}

func (s *ScsResult) GetLine() string {
	indexKey := strings.Index(s.Filename, "(")
	indexComma := strings.Index(s.Filename, ",")

	if indexKey < 0 || indexComma < 0 {
		return ""
	}

	return s.Filename[indexKey+1 : indexComma]
}

func (s *ScsResult) GetColumn() string {
	indexComma := strings.Index(s.Filename, ",")
	indexKey := strings.Index(s.Filename, ")")

	if indexKey < 0 || indexComma < 0 {
		return ""
	}

	return s.Filename[indexComma+1 : indexKey]
}

func (s *ScsResult) GetFilename() string {
	index := strings.Index(s.Filename, "(")

	if index < 0 {
		return ""
	}

	return s.Filename[0:index]
}

func (s *ScsResult) GetSeverity() severity.Severity {
	if s.ErrorID == "" {
		return severity.Unknown
	}

	return s.getVulnerabilityMap()[s.ErrorID]
}

func (s *ScsResult) getVulnerabilityMap() map[string]severity.Severity {
	values := map[string]severity.Severity{}

	for key, value := range severities.MapCriticalValues() {
		values[key] = value
	}
	for key, value := range severities.MapHighValues() {
		values[key] = value
	}
	for key, value := range severities.MapMediumValues() {
		values[key] = value
	}
	for key, value := range severities.MapLowValues() {
		values[key] = value
	}
	return values
}
