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

package nancy

import (
	"encoding/json"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/go/nancy/entities"
	"github.com/ZupIT/horusec/internal/services/formatters/go/nancy/enums"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnHash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
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
	if f.ToolIsToIgnore(tools.Nancy) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Nancy.ToString())
		return
	}

	f.SetAnalysisError(f.startNancy(projectSubPath), tools.Nancy, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Nancy, languages.Go)
}

func (f *Formatter) startNancy(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Nancy, languages.Go)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	if output == "" {
		return nil
	}

	return f.processOutput(output, projectSubPath)
}

func (f *Formatter) processOutput(output, projectSubPath string) error {
	analysis := &entities.Analysis{}

	if err := json.Unmarshal([]byte(f.getOutputText(output)), &analysis); err != nil {
		return err
	}

	for _, vulnerable := range analysis.Vulnerable {
		f.AddNewVulnerabilityIntoAnalysis(
			f.setVulnerabilityData(vulnerable.GetVulnerability(), vulnerable, projectSubPath))
	}

	return nil
}

func (f *Formatter) getOutputText(output string) string {
	index := strings.Index(output, enums.JSONIndex)
	if index < 0 {
		return output
	}

	return output[index:]
}

func (f *Formatter) setVulnerabilityData(vulnData *entities.Vulnerability,
	vulnerable *entities.Vulnerable, projectSubPath string) *vulnerability.Vulnerability {
	code, filepath, line := file.GetDependencyCodeFilepathAndLine(
		f.GetConfigProjectPath(), projectSubPath, enums.GoModulesExt, vulnerable.GetDependency())
	vuln := f.getDefaultVulnerabilitySeverity()
	vuln.Severity = vulnData.GetSeverity()
	vuln.Details = vulnData.GetDescription()
	vuln.Confidence = confidence.High
	vuln.Code = code
	vuln.Line = line
	vuln.File = filepath
	vuln = vulnHash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.Language = languages.Go
	vulnerabilitySeverity.SecurityTool = tools.Nancy
	return vulnerabilitySeverity
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.Nancy),
		Language: languages.Go,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.Go), images.Go)
}
