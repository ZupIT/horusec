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

	horusecEntities "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	vulnEntity "github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	horusecSeverity "github.com/ZupIT/horusec-devkit/pkg/enums/severities"

	"github.com/ZupIT/horusec/internal/entities/sonarqube"
)

type SonarQube struct {
	analysis *horusecEntities.Analysis
}

func NewSonarQube(analysis *horusecEntities.Analysis) *SonarQube {
	return &SonarQube{
		analysis: analysis,
	}
}

func (sq *SonarQube) ConvertVulnerabilityToSonarQube() (report sonarqube.Report) {
	report.Issues = []sonarqube.Issue{}
	for index := range sq.analysis.AnalysisVulnerabilities {
		vulnerability := sq.analysis.AnalysisVulnerabilities[index].Vulnerability

		issue := sq.formatReportStruct(&vulnerability)

		report.Issues = append(report.Issues, *issue)
	}

	return report
}

func (sq *SonarQube) formatReportStruct(vulnerability *vulnEntity.Vulnerability) (issue *sonarqube.Issue) {
	issue = sq.newIssue(vulnerability)

	convertedVulnerabilityLine, _ := strconv.Atoi(vulnerability.Line)
	convertedVulnerabilityColumn, _ := strconv.Atoi(vulnerability.Column)

	issue.PrimaryLocation.Range.StartLine = sq.shouldBeGreatherThanZero(convertedVulnerabilityLine)
	issue.PrimaryLocation.Range.StartColumn = sq.shouldBeGreatherThanZero(convertedVulnerabilityColumn)
	return issue
}

func (sq *SonarQube) shouldBeGreatherThanZero(v int) int {
	if v > 0 {
		return v
	}

	return 1
}

func (sq *SonarQube) newIssue(vulnerability *vulnEntity.Vulnerability) *sonarqube.Issue {
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
		horusecSeverity.Critical: "BLOCKER",
		horusecSeverity.High:     "CRITICAL",
		horusecSeverity.Medium:   "MAJOR",
		horusecSeverity.Low:      "MINOR",
		horusecSeverity.Unknown:  "INFO",
		horusecSeverity.Info:     "INFO",
	}
}
