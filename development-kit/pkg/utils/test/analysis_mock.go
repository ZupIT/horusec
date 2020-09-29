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

package test

import (
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/google/uuid"
)

// CreateAnalysisMock creates a mocked plain entity to use in test suites.
func CreateAnalysisMock() *horusec.Analysis {
	return &horusec.Analysis{
		ID:              uuid.New(),
		RepositoryID:    uuid.New(),
		CompanyID:       uuid.New(),
		CreatedAt:       time.Now(),
		Vulnerabilities: ReturnEachTypeOfVulnerability(),
	}
}

func GetGoVulnerabilityWithSeverity(severity severity.Severity) horusec.Vulnerability {
	return horusec.Vulnerability{
		Line:          "10",
		Column:        "0",
		Confidence:    "HIGH",
		File:          "main.go",
		Code:          "password = 'test'",
		Details:       "hard coded password",
		SecurityTool:  tools.GoSec,
		Language:      languages.Go,
		Severity:      severity,
		CommitAuthor:  "User",
		CommitEmail:   "user@email.com",
		CommitHash:    "123456789",
		CommitMessage: "Some commit",
		CommitDate:    time.Now().String(),
	}
}

// ReturnEachTypeOfVulnerability generates a generic []Vulnerability
// with 1 vulnerability of each tool/language.
// The Severity and CommitAuthor are empty on purpose
func ReturnEachTypeOfVulnerability() []horusec.Vulnerability {
	return []horusec.Vulnerability{
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			SecurityTool:    tools.GoSec,
			Language:        languages.Go,
			Severity:        severity.Low,
		},
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			SecurityTool:    tools.SecurityCodeScan,
			Language:        languages.DotNet,
			Severity:        severity.Low,
		},
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			SecurityTool:    tools.Brakeman,
			Language:        languages.Ruby,
			Severity:        severity.Low,
		},
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			SecurityTool:    tools.NpmAudit,
			Language:        languages.Javascript,
			Severity:        severity.Low,
		},
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			SecurityTool:    tools.YarnAudit,
			Language:        languages.Javascript,
			Severity:        severity.Low,
		},
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			SecurityTool:    tools.Bandit,
			Language:        languages.Python,
			Severity:        severity.Low,
		},
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			SecurityTool:    tools.Bandit,
			Language:        languages.Python,
			Severity:        severity.Low,
		},
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			Language:        languages.Leaks,
			Severity:        severity.High,
		},
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			SecurityTool:    tools.GitLeaks,
			Language:        languages.Leaks,
			Severity:        severity.High,
		},
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			SecurityTool:    tools.SpotBugs,
			Language:        languages.Java,
			Severity:        severity.Low,
		},
		{
			Line:            "",
			Column:          "",
			Confidence:      "",
			File:            "",
			Code:            "",
			Details:         "",
			Type:            "",
			VulnerableBelow: "",
			Version:         "",
			SecurityTool:    tools.SpotBugs,
			Language:        languages.Kotlin,
			Severity:        severity.Low,
		},
	}
}
