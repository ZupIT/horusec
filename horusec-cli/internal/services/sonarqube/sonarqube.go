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

import (
	"strconv"

	"github.com/ZupIT/horusec/horusec-cli/internal/entities/sonarqube"

	horusecEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	horusecSeverity "github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
)

type Interface interface {
	ConvertVulnerabilityDataToSonarQube() sonarqube.Report
}

type SonarQube struct {
	analysis *horusecEntities.Analysis
}

func NewSonarQube(analysis *horusecEntities.Analysis) Interface {
	return &SonarQube{
		analysis: analysis,
	}
}

func (sq *SonarQube) ConvertVulnerabilityDataToSonarQube() (report sonarqube.Report) {
	for index := range sq.analysis.Vulnerabilities {
		vulnerability := sq.analysis.Vulnerabilities[index]

		issue := sq.formatReportStruct(&vulnerability)

		report.Issues = append(report.Issues, *issue)
	}

	return report
}

func (sq *SonarQube) formatReportStruct(vulnerability *horusecEntities.Vulnerability) (issue *sonarqube.Issue) {
	issue = sq.newIssue(vulnerability)

	convertedVulnerabilityLine, _ := strconv.Atoi(vulnerability.Line)
	convertedVulnerabilityColumn, _ := strconv.Atoi(vulnerability.Column)

	issue.PrimaryLocation.Range.StartLine = convertedVulnerabilityLine
	issue.PrimaryLocation.Range.StartColumn = convertedVulnerabilityColumn
	return issue
}

func (sq *SonarQube) newIssue(vulnerability *horusecEntities.Vulnerability) *sonarqube.Issue {
	return &sonarqube.Issue{
		EngineID: "horusec",
		Type:     "VULNERABILITY",
		Severity: sq.convertHorusecSeverityToSonarQube(vulnerability.Severity),
		RuleID:   vulnerability.SecurityTool.ToString(),
		PrimaryLocation: sonarqube.Location{
			Message:  vulnerability.Details,
			Filepath: vulnerability.File,
		},
	}
}

func (sq *SonarQube) convertHorusecSeverityToSonarQube(severity horusecSeverity.Severity) string {
	return sq.getSonarQubeSeverityMap()[severity]
}

func (sq *SonarQube) getSonarQubeSeverityMap() map[horusecSeverity.Severity]string {
	return map[horusecSeverity.Severity]string{
		horusecSeverity.NoSec:  "INFO",
		horusecSeverity.Audit:  "INFO",
		horusecSeverity.Low:    "MINOR",
		horusecSeverity.Medium: "MAJOR",
		horusecSeverity.High:   "BLOCKER",
	}
}
