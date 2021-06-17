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
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	errorsEnums "github.com/ZupIT/horusec/internal/enums/errors"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/scs/entities"
	severitiesScs "github.com/ZupIT/horusec/internal/services/formatters/csharp/scs/severities"
	fileUtils "github.com/ZupIT/horusec/internal/utils/file"
	vulnHash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

type Formatter struct {
	formatters.IService
	severities          map[string]severities.Severity
	vulnerabilitiesByID map[string]*entities.Rule
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		IService: service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.SecurityCodeScan) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.SecurityCodeScan.ToString())
		return
	}

	f.SetAnalysisError(f.startSecurityCodeScan(projectSubPath), tools.SecurityCodeScan, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.SecurityCodeScan, languages.CSharp)
}

func (f *Formatter) startSecurityCodeScan(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.SecurityCodeScan, languages.CSharp)

	analysisData := f.getDockerConfig(projectSubPath)
	if err := f.verifyIsSolutionError(analysisData.CMD); err != nil {
		return err
	}

	output, err := f.ExecuteContainer(analysisData)
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) parseOutput(output string) error {
	analysis := &entities.Analysis{}

	if err := json.Unmarshal([]byte(output), &analysis); err != nil {
		return err
	}

	f.setSeveritiesAndVulnsByID(analysis)
	for _, result := range analysis.GetRun().Results {
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(result))
	}

	return nil
}

func (f *Formatter) setSeveritiesAndVulnsByID(analysis *entities.Analysis) {
	f.severities = f.getVulnerabilityMap()
	f.vulnerabilitiesByID = analysis.MapVulnerabilitiesByID()
}

func (f *Formatter) setVulnerabilityData(result *entities.Result) *vulnerability.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = f.GetSeverity(result.RuleID)
	data.Details = f.GetDetails(result.RuleID, result.GetVulnName())
	data.Line = result.GetLine()
	data.Column = result.GetColumn()
	data.File = result.GetFile()
	data.Code = fileUtils.GetCode(f.GetConfigProjectPath(), result.GetFile(), result.GetLine())
	data = vulnHash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.SecurityCodeScan
	vulnerabilitySeverity.Language = languages.CSharp
	return vulnerabilitySeverity
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD: f.AddWorkDirInCmd(CMD, fileUtils.GetSubPathByExtension(
			f.GetConfigProjectPath(), projectSubPath, "*.sln"), tools.SecurityCodeScan),
		Language: languages.CSharp,
	}

	analysisData.SetSlnName(fileUtils.GetFilenameByExt(f.GetConfigProjectPath(), projectSubPath, ".sln"))
	return analysisData.SetData(f.GetCustomImageByLanguage(languages.CSharp), images.Csharp)
}

func (f *Formatter) verifyIsSolutionError(cmd string) error {
	if strings.Contains(cmd, "solution file not found") {
		return errorsEnums.ErrSolutionNotFound
	}

	return nil
}

func (f *Formatter) GetSeverity(ruleID string) severities.Severity {
	if ruleID == "" {
		return severities.Unknown
	}

	return f.severities[ruleID]
}

func (f Formatter) GetDetails(ruleID, vulnName string) string {
	if ruleID == "" {
		return vulnName
	}

	return f.vulnerabilitiesByID[ruleID].GetDescription(vulnName)
}

func (f *Formatter) getVulnerabilityMap() map[string]severities.Severity {
	values := map[string]severities.Severity{}
	for key, value := range severitiesScs.MapCriticalValues() {
		values[key] = value
	}
	for key, value := range severitiesScs.MapHighValues() {
		values[key] = value
	}
	for key, value := range severitiesScs.MapMediumValues() {
		values[key] = value
	}
	for key, value := range severitiesScs.MapLowValues() {
		values[key] = value
	}

	return values
}
