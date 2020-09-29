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

package dotnet

import (
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/dotnet/severities"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
)

type Output struct {
	Filename      string `json:"Filename"`
	IssueSeverity string `json:"IssueSeverity"`
	ErrorID       string `json:"ErrorID"`
	IssueText     string `json:"IssueText"`
}

func (o *Output) IsValid() bool {
	return !o.IsEmpty() && o.IsSecurityIssue()
}

func (o *Output) IsEmpty() bool {
	return o.Filename == "" || o.IssueSeverity == "" || o.ErrorID == "" || o.IssueText == ""
}

func (o *Output) IsSecurityIssue() bool {
	if o.ErrorID == "" {
		return false
	}

	return o.ErrorID[0:2] == "SC"
}

func (o *Output) GetLine() string {
	indexKey := strings.Index(o.Filename, "(")
	indexComma := strings.Index(o.Filename, ",")

	if indexKey < 0 || indexComma < 0 {
		return ""
	}

	return o.Filename[indexKey+1 : indexComma]
}

func (o *Output) GetColumn() string {
	indexComma := strings.Index(o.Filename, ",")
	indexKey := strings.Index(o.Filename, ")")

	if indexKey < 0 || indexComma < 0 {
		return ""
	}

	return o.Filename[indexComma+1 : indexKey]
}

func (o *Output) GetFilename() string {
	index := strings.Index(o.Filename, "(")

	if index < 0 {
		return ""
	}

	return o.Filename[0:index]
}

func (o *Output) GetSeverity() severity.Severity {
	if severities.IsLowSeverity(o.ErrorID) {
		return severity.Low
	}

	if severities.IsMediumSeverity(o.ErrorID) {
		return severity.Medium
	}

	if severities.IsHighSeverity(o.ErrorID) {
		return severity.High
	}

	return severity.NoSec
}
