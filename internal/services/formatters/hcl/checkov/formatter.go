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

package checkov

import (
	"encoding/json"

	"github.com/pborman/ansi"

	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec/internal/enums/images"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/hcl/checkov/entities"
)

type Formatter struct {
	formatters.IService
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.Checkov) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Checkov.ToString())
		return
	}

	f.SetAnalysisError(f.startCheckov(projectSubPath), tools.Checkov, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Checkov, languages.HCL)
}

func (f *Formatter) startCheckov(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Checkov, languages.HCL)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.Checkov),
		Language: languages.HCL,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.HCL), images.HCL)
}

func (f *Formatter) parseOutput(output string) error {
	var vuln *entities.Vulnerability

	binary, _ := ansi.Strip([]byte(output))
	if err := json.Unmarshal(binary, &vuln); err != nil {
		return err
	}

	for _, check := range vuln.Results.FailedChecks {
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(check))
	}

	return nil
}

func (f *Formatter) setVulnerabilityData(check *entities.Check) *vulnerability.Vulnerability {
	vuln := f.getDefaultVulnerabilityData()
	vuln.Severity = check.GetSeverity()
	vuln.Details = check.GetDetails()
	vuln.Line = check.GetStartLine()
	vuln.Code = f.GetCodeWithMaxCharacters(check.GetCode(), 0)
	vuln.File = f.RemoveSrcFolderFromPath(check.GetFilename())
	vuln = vulnhash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}

func (f *Formatter) getDefaultVulnerabilityData() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.Checkov
	vulnerabilitySeverity.Language = languages.HCL
	return vulnerabilitySeverity
}
