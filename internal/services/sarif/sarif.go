// Copyright 2022 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package sarif

import (
	"strconv"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"

	"github.com/ZupIT/horusec/cmd/app/version"
)

type Sarif struct {
	analysiss *analysis.Analysis

	resultsByTool          map[string][]Result
	rulesByToolAndID       map[string]map[string]Rule
	artifactsByToolAndName map[string]map[string]Artifact
}

func NewSarif(analysiss *analysis.Analysis) *Sarif {
	return &Sarif{
		analysiss:              analysiss,
		resultsByTool:          make(map[string][]Result),
		rulesByToolAndID:       make(map[string]map[string]Rule),
		artifactsByToolAndName: make(map[string]map[string]Artifact),
	}
}

func (s *Sarif) ConvertVulnerabilityToSarif() (report Report) {
	report.Runs = []ReportRun{}
	s.populateReferenceMaps(&report)
	s.buildReportRun(&report)

	// SARIF output format version/schema
	report.Version = "2.1.0"
	report.SchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

	return report
}

// populateReferenceMaps iterates all vulnerabilities and break them into the maps/associations necessary
// to build the SARIF report; resultsByTool, artifactsByToolAndName, rulesByToolAndID.
// resultsByTool: Groups individual vuln issue types into the tool which created them
// artifactsByToolAndName: Groups areas of the scanned code into the tool/issue type creating them
// rulesByToolAndId: Groups issue types which are presented by the tool, based on the vulns given
// This prevents the need from iterating over the entire vuln list multiple times.
func (s *Sarif) populateReferenceMaps(report *Report) {
	runsByTool := make(map[string]ReportRun)
	for index := range s.analysiss.AnalysisVulnerabilities {
		vuln := &s.analysiss.AnalysisVulnerabilities[index].Vulnerability
		if _, exists := runsByTool[string(vuln.SecurityTool)]; !exists {
			report.Runs = append(report.Runs, s.initToolStructure(vuln, runsByTool))
		}
		s.resultsByTool[string(vuln.SecurityTool)] = append(s.resultsByTool[string(vuln.SecurityTool)], s.newResult(vuln))
		artifact := s.newArtifact(vuln)
		s.artifactsByToolAndName[string(vuln.SecurityTool)][artifact.Location.URI] = artifact
		rule := s.newRule(vuln)
		s.rulesByToolAndID[string(vuln.SecurityTool)][rule.ID] = rule
	}
}

// buildReportRun builds a single "run" for the report. For SARIF, a "run" has a single tool.
// Therefore, each group of vulnerabilities reported by a specific tool are all
// organized in the same "run".
func (s *Sarif) buildReportRun(report *Report) {
	for idx, runReport := range report.Runs {
		for _, artifact := range s.artifactsByToolAndName[runReport.Tool.Driver.Name] {
			report.Runs[idx].Artifacts = append(report.Runs[idx].Artifacts, artifact)
		}
		for _, rule := range s.rulesByToolAndID[runReport.Tool.Driver.Name] {
			report.Runs[idx].Tool.Driver.Rules = append(report.Runs[idx].Tool.Driver.Rules, rule)
		}
		report.Runs[idx].Results = append(report.Runs[idx].Results, s.resultsByTool[runReport.Tool.Driver.Name]...)
	}
}

// initToolStructure initializes the structure for a single report "run", as well as updating
// the association maps in the SARIF object to reflect the run's existence
func (s *Sarif) initToolStructure(
	vulnerabilityy *vulnerability.Vulnerability,
	runsByTool map[string]ReportRun,
) ReportRun {
	s.rulesByToolAndID[string(vulnerabilityy.SecurityTool)] = make(map[string]Rule)
	s.artifactsByToolAndName[string(vulnerabilityy.SecurityTool)] = make(map[string]Artifact)

	reportRun := ReportRun{
		Tool: s.newTool(vulnerabilityy),
	}

	runsByTool[string(vulnerabilityy.SecurityTool)] = reportRun

	return reportRun
}

func (s *Sarif) convertNonZeroIntStr(str string) int {
	newInt, _ := strconv.Atoi(str)
	if newInt > 0 {
		return newInt
	}
	return 1
}

func (s *Sarif) newTool(vulnerabilityy *vulnerability.Vulnerability) ScanTool {
	return ScanTool{
		Driver: ScanToolDriver{
			Name:               vulnerabilityy.SecurityTool.ToString(),
			MoreInformationURI: "https://docs.horusec.io/docs/cli/analysis-tools/overview/",
			Version:            version.Version,
		},
	}
}

func (s *Sarif) newRule(vulnerabilityy *vulnerability.Vulnerability) Rule {
	return Rule{
		ID: vulnerabilityy.RuleID,
		ShortDescription: TextDisplayComponent{
			Text: vulnerabilityy.Details,
		},
		FullDescription: TextDisplayComponent{
			Text: vulnerabilityy.Details,
		},
		HelpURI: "https://docs.horusec.io/docs/cli/analysis-tools/overview/",
		Name:    strings.Split(vulnerabilityy.Details, "\n")[0],
	}
}

func (s *Sarif) newArtifact(vulnerabilityy *vulnerability.Vulnerability) Artifact {
	return Artifact{
		Location: LocationComponent{
			URI: vulnerabilityy.File,
		},
	}
}

func (s *Sarif) newResult(vulnerabilityy *vulnerability.Vulnerability) Result {
	return Result{
		Message: TextDisplayComponent{
			Text: vulnerabilityy.Details,
		},
		Level:     ResultLevel(s.convertHorusecSeverityToSarif(vulnerabilityy.Severity)),
		Locations: []Location{s.createLocation(vulnerabilityy)},
		RuleID:    vulnerabilityy.RuleID,
	}
}

func (s *Sarif) createLocation(vulnerabilityy *vulnerability.Vulnerability) Location {
	return Location{
		PhysicalLocation: PhysicalLocation{
			ArtifactLocation: LocationComponent{
				URI: vulnerabilityy.File,
			},
			Region: SnippetRegion{
				Snippet: TextDisplayComponent{
					Text: vulnerabilityy.Code,
				},
				StartLine:   s.convertNonZeroIntStr(vulnerabilityy.Line),
				StartColumn: s.convertNonZeroIntStr(vulnerabilityy.Column),
			},
		},
	}
}

func (s *Sarif) convertHorusecSeverityToSarif(severity severities.Severity) string {
	return s.getSarifSeverityMap()[severity]
}

func (s *Sarif) getSarifSeverityMap() map[severities.Severity]string {
	return map[severities.Severity]string{
		severities.Critical: Error,
		severities.High:     Error,
		severities.Medium:   Warning,
		severities.Low:      Note,
		severities.Unknown:  Note,
		severities.Info:     Note,
	}
}
