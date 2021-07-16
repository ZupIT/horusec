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

package mock

import (
	"time"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	enumsAnalysis "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	enumsVulnerability "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/google/uuid"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
)

// CreateAnalysisMock creates a mocked plain entity to use in test suites.
func CreateAnalysisMock() *analysis.Analysis {
	mock := &analysis.Analysis{
		ID:                      uuid.New(),
		RepositoryID:            uuid.New(),
		WorkspaceID:             uuid.New(),
		Status:                  enumsAnalysis.Success,
		Errors:                  "",
		CreatedAt:               time.Now(),
		FinishedAt:              time.Now(),
		AnalysisVulnerabilities: []analysis.AnalysisVulnerabilities{},
	}
	vuls := ReturnEachTypeOfVulnerability()
	for key := range vuls {
		mock.AnalysisVulnerabilities = append(mock.AnalysisVulnerabilities, analysis.AnalysisVulnerabilities{
			VulnerabilityID: vuls[key].VulnerabilityID,
			AnalysisID:      mock.ID,
			Vulnerability:   vuls[key],
		})
	}
	return mock
}

// ReturnEachTypeOfVulnerability generates a generic []Vulnerability
// with 1 vulnerability of each tool/language.
// The Severity and CommitAuthor are empty on purpose
func ReturnEachTypeOfVulnerability() []vulnerability.Vulnerability {
	return []vulnerability.Vulnerability{
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates GoSec",
			SecurityTool:    tools.GoSec,
			Language:        languages.Go,
			Severity:        severities.Low,
			Type:            enumsVulnerability.Vulnerability,
		}),
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates SecurityCodeScan",
			SecurityTool:    tools.SecurityCodeScan,
			Language:        languages.CSharp,
			Severity:        severities.Medium,
			VulnHash:        uuid.New().String(),
			Type:            enumsVulnerability.Vulnerability,
		}),
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates Brakeman",
			SecurityTool:    tools.Brakeman,
			Language:        languages.Ruby,
			Severity:        severities.High,
			VulnHash:        uuid.New().String(),
			Type:            enumsVulnerability.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates NpmAudit",
			SecurityTool:    tools.NpmAudit,
			Language:        languages.Javascript,
			Severity:        severities.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumsVulnerability.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates YarnAudit",
			SecurityTool:    tools.YarnAudit,
			Language:        languages.Javascript,
			Severity:        severities.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumsVulnerability.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates Bandit",
			SecurityTool:    tools.Bandit,
			Language:        languages.Python,
			Severity:        severities.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumsVulnerability.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates Safety",
			SecurityTool:    tools.Safety,
			Language:        languages.Python,
			Severity:        severities.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumsVulnerability.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates HorusecLeaks",
			SecurityTool:    tools.HorusecEngine,
			Language:        languages.Leaks,
			Severity:        severities.High,
			VulnHash:        uuid.New().String(),
			Type:            enumsVulnerability.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates GitLeaks",
			SecurityTool:    tools.GitLeaks,
			Language:        languages.Leaks,
			Severity:        severities.High,
			VulnHash:        uuid.New().String(),
			Type:            enumsVulnerability.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates HorusecJava",
			SecurityTool:    tools.HorusecEngine,
			Language:        languages.Java,
			Severity:        severities.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumsVulnerability.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&vulnerability.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High,
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates HorusecKotlin",
			SecurityTool:    tools.HorusecEngine,
			Language:        languages.Kotlin,
			Severity:        severities.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumsVulnerability.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
	}
}
