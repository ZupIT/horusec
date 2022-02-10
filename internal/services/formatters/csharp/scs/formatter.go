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

package scs

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	fileutils "github.com/ZupIT/horusec/internal/utils/file"
	vulnHash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

var (
	// ErrSolutionNotFound occurs when a .sln file not found on dotnet project.
	//
	// nolint: lll
	ErrSolutionNotFound = errors.New("security code scan failed to execute. The current working directory does not contain a solution file")

	// ErrBuildProject occurs when SCS fail to build the dotnet project.
	ErrBuildProject = errors.New("project failed to build. Fix the project issues and try again")
)

const (
	BuildFailedOutput    = "Msbuild failed when processing the file"
	SolutionFileNotFound = "solution file not found"
	solutionExt          = ".sln"
)

type Formatter struct {
	formatters.IService
	severities          map[string]severities.Severity
	vulnerabilitiesByID map[string]*scsRule
}

func NewFormatter(service formatters.IService) *Formatter {
	return &Formatter{
		IService: service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.SecurityCodeScan) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.SecurityCodeScan.ToString())
		return
	}

	output, err := f.startSecurityCodeScan(projectSubPath)
	f.SetAnalysisError(err, tools.SecurityCodeScan, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.SecurityCodeScan, languages.CSharp)
}

func (f *Formatter) startSecurityCodeScan(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.SecurityCodeScan, languages.CSharp)

	analysisData := f.getDockerConfig(projectSubPath)

	outputContainer, err := f.ExecuteContainer(analysisData)
	if err != nil {
		return "", err
	}

	output, err := f.checkOutputErrors(outputContainer)
	if err != nil {
		return outputContainer, err
	}

	return output, f.parseOutput(output)
}

func (f *Formatter) parseOutput(output string) error {
	analysis := new(scsAnalysis)

	if err := json.Unmarshal([]byte(output), &analysis); err != nil {
		return err
	}

	f.setSeveritiesAndVulnsByID(analysis)

	f.addVulnIntoAnalysis(analysis)

	return nil
}

func (f *Formatter) addVulnIntoAnalysis(analysis *scsAnalysis) {
	for _, result := range analysis.getRun().Results {
		vuln, err := f.newVulnerability(result)
		if err != nil {
			f.SetAnalysisError(err, tools.SecurityCodeScan, err.Error(), "")
			continue
		}
		f.AddNewVulnerabilityIntoAnalysis(vuln)
	}
}

func (f *Formatter) setSeveritiesAndVulnsByID(analysis *scsAnalysis) {
	f.severities = f.getVulnerabilityMap()
	f.vulnerabilitiesByID = analysis.vulnerabilitiesByID()
}

// nolint: funlen // needs to be bigger
func (f *Formatter) newVulnerability(result *scsResult) (*vulnerability.Vulnerability, error) {
	code, err := fileutils.GetCode(f.GetConfigProjectPath(), result.getFile(), result.getLine())
	if err != nil {
		return nil, err
	}
	vuln := &vulnerability.Vulnerability{
		SecurityTool: tools.SecurityCodeScan,
		Language:     languages.CSharp,
		Severity:     f.getSeverity(result.RuleID),
		Details:      f.getDetails(result.RuleID, result.getVulnName()),
		Line:         result.getLine(),
		Column:       result.getColumn(),
		File:         result.getFile(),
		Code:         code,
	}

	return f.SetCommitAuthor(vulnHash.Bind(vuln)), err
}

// nolint: funlen
func (f *Formatter) getDockerConfig(projectSubPath string) *docker.AnalysisData {
	analysisData := &docker.AnalysisData{
		CMD: f.AddWorkDirInCmd(
			CMD,
			fileutils.GetSubPathByExtension(f.GetConfigProjectPath(), projectSubPath, solutionExt),
			tools.SecurityCodeScan,
		),
		Language: languages.CSharp,
	}

	filename, err := fileutils.GetFilenameByExt(f.GetConfigProjectPath(), projectSubPath, solutionExt)
	if err != nil {
		logger.LogError(messages.MsgErrorGetFilenameByExt, err)
	}

	analysisData.SetSlnName(filename)

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.CSharp), images.Csharp)
}

func (f *Formatter) getSeverity(ruleID string) severities.Severity {
	if ruleID == "" {
		return severities.Unknown
	}

	return f.severities[ruleID]
}

func (f Formatter) getDetails(ruleID, vulnName string) string {
	if ruleID == "" {
		return vulnName
	}

	return f.vulnerabilitiesByID[ruleID].getDescription(vulnName)
}

// nolint: funlen
func (f *Formatter) getVulnerabilityMap() map[string]severities.Severity {
	values := make(map[string]severities.Severity)

	for key, value := range criticalSeverities() {
		values[key] = value
	}

	for key, value := range highSeverities() {
		values[key] = value
	}

	for key, value := range mediumSeverities() {
		values[key] = value
	}

	for key, value := range lowSevetiries() {
		values[key] = value
	}

	return values
}

func (f *Formatter) checkOutputErrors(output string) (string, error) {
	if strings.Contains(output, BuildFailedOutput) {
		return output, ErrBuildProject
	}

	if strings.Contains(output, SolutionFileNotFound) {
		return output, ErrSolutionNotFound
	}

	return output, nil
}
