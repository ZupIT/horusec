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

package python

import "github.com/ZupIT/horusec/development-kit/pkg/enums/severity"

type BanditOutput struct {
	Results []BanditResult `json:"results"`
}

type SafetyOutput struct {
	Issues []SafetyIssues `json:"issues"`
}

type BanditResult struct {
	Code            string            `json:"code"`
	FileName        string            `json:"filename"`
	IssueConfidence string            `json:"issue_confidence"`
	IssueSeverity   severity.Severity `json:"issue_severity"`
	IssueText       string            `json:"issue_text"`
	LineNumber      int               `json:"line_number"`
	LineRange       []int             `json:"line_range"`
	MoreInfo        string            `json:"more_info"`
	TestID          string            `json:"test_id"`
	TestName        string            `json:"test_name"`
}

type SafetyIssues struct {
	Dependency       string `json:"dependency"`
	VulnerableBelow  string `json:"vulnerable_below"`
	InstalledVersion string `json:"installed_version"`
	Description      string `json:"description"`
	ID               string `json:"id"`
}
