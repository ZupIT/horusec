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

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

type SonarQube struct {
	analysis *analysis.Analysis
}

func NewSonarQube(analysiss *analysis.Analysis) *SonarQube {
	return &SonarQube{
		analysis: analysiss,
	}
}

func (sq *SonarQube) ConvertVulnerabilityToSonarQube() (report Report) {
	report.Issues = []Issue{}
	for index := range sq.analysis.AnalysisVulnerabilities {
		vuln := sq.analysis.AnalysisVulnerabilities[index].Vulnerability

		issue := sq.formatReportStruct(&vuln)

		report.Issues = append(report.Issues, *issue)
	}

	return report
}

func (sq *SonarQube) formatReportStruct(vuln *vulnerability.Vulnerability) (issue *Issue) {
	issue = sq.newIssue(vuln)

	convertedVulnerabilityLine, _ := strconv.Atoi(vuln.Line)
	convertedVulnerabilityColumn, _ := strconv.Atoi(vuln.Column)

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

func (sq *SonarQube) newIssue(vuln *vulnerability.Vulnerability) *Issue {
	return &Issue{
		EngineID: "horusec",
		Type:     "VULNERABILITY",
		Severity: sq.convertHorusecSeverityToSonarQube(vuln.Severity),
		RuleID:   vuln.SecurityTool.ToString(),
		PrimaryLocation: Location{
			Message:  vuln.Details,
			Filepath: vuln.File,
		},
	}
}

func (sq *SonarQube) convertHorusecSeverityToSonarQube(severity severities.Severity) string {
	return sq.getSonarQubeSeverityMap()[severity]
}

func (sq *SonarQube) getSonarQubeSeverityMap() map[severities.Severity]string {
	return map[severities.Severity]string{
		severities.Critical: "BLOCKER",
		severities.High:     "CRITICAL",
		severities.Medium:   "MAJOR",
		severities.Low:      "MINOR",
		severities.Unknown:  "INFO",
		severities.Info:     "INFO",
	}
}
