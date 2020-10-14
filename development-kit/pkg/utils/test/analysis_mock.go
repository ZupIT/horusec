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
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	enumHorusec "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/google/uuid"
)

// CreateAnalysisMock creates a mocked plain entity to use in test suites.
func CreateAnalysisMock() *horusec.Analysis {
	analysis := &horusec.Analysis{
		ID:                      uuid.New(),
		RepositoryID:            uuid.New(),
		CompanyID:               uuid.New(),
		Status:                  enumHorusec.Success,
		Errors:                  "",
		CreatedAt:               time.Now(),
		FinishedAt:              time.Now(),
		AnalysisVulnerabilities: []horusec.AnalysisVulnerabilities{},
	}
	vuls := ReturnEachTypeOfVulnerability()
	for key := range vuls {
		analysis.AnalysisVulnerabilities = append(analysis.AnalysisVulnerabilities, horusec.AnalysisVulnerabilities{
			VulnerabilityID: vuls[key].VulnerabilityID,
			AnalysisID:      analysis.ID,
			Vulnerability:   vuls[key],
		})
	}
	return analysis
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
		VulnHash:      "123456789",
		Type:          enumHorusec.Vulnerability,
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
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates GoSec",
			SecurityTool:    tools.GoSec,
			Language:        languages.Go,
			Severity:        severity.Low,
			Type:            enumHorusec.Vulnerability,
		}),
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates SecurityCodeScan",
			SecurityTool:    tools.SecurityCodeScan,
			Language:        languages.DotNet,
			Severity:        severity.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumHorusec.Vulnerability,
		}),
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates Brakeman",
			SecurityTool:    tools.Brakeman,
			Language:        languages.Ruby,
			Severity:        severity.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumHorusec.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates NpmAudit",
			SecurityTool:    tools.NpmAudit,
			Language:        languages.Javascript,
			Severity:        severity.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumHorusec.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates YarnAudit",
			SecurityTool:    tools.YarnAudit,
			Language:        languages.Javascript,
			Severity:        severity.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumHorusec.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates Bandit",
			SecurityTool:    tools.Bandit,
			Language:        languages.Python,
			Severity:        severity.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumHorusec.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates Safety",
			SecurityTool:    tools.Safety,
			Language:        languages.Python,
			Severity:        severity.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumHorusec.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates HorusecLeaks",
			SecurityTool:    tools.HorusecLeaks,
			Language:        languages.Leaks,
			Severity:        severity.High,
			VulnHash:        uuid.New().String(),
			Type:            enumHorusec.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates GitLeaks",
			SecurityTool:    tools.GitLeaks,
			Language:        languages.Leaks,
			Severity:        severity.High,
			VulnHash:        uuid.New().String(),
			Type:            enumHorusec.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates HorusecJava",
			SecurityTool:    tools.HorusecJava,
			Language:        languages.Java,
			Severity:        severity.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumHorusec.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
		*vulnhash.Bind(&horusec.Vulnerability{
			VulnerabilityID: uuid.New(),
			Line:            "1",
			Column:          "0",
			Confidence:      confidence.High.ToString(),
			File:            "cert.pem",
			Code:            "-----BEGIN CERTIFICATE-----",
			Details:         "Found SSH and/or x.509 Cerficates HorusecKotlin",
			SecurityTool:    tools.HorusecKotlin,
			Language:        languages.Kotlin,
			Severity:        severity.Low,
			VulnHash:        uuid.New().String(),
			Type:            enumHorusec.Vulnerability,
			CommitAuthor:    "",
			CommitEmail:     "",
			CommitHash:      "",
			CommitMessage:   "",
			CommitDate:      "",
		}),
	}
}
