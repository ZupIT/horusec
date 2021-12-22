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

package dependencycheck

import (
	"encoding/json"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	dependencyCheckEntities "github.com/ZupIT/horusec/internal/services/formatters/generic/dependency_check/entities"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
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
	if f.ToolIsToIgnore(tools.OwaspDependencyCheck) || f.IsDockerDisabled() || f.IsOwaspDependencyCheckDisable() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.OwaspDependencyCheck.ToString())
		return
	}

	output, err := f.startDependencyCheck(projectSubPath)
	f.SetAnalysisError(err, tools.OwaspDependencyCheck, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.OwaspDependencyCheck, languages.Generic)
}

func (f *Formatter) startDependencyCheck(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.OwaspDependencyCheck, languages.Generic)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		return output, err
	}

	return output, f.parseOutput(output)
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.OwaspDependencyCheck),
		Language: languages.Generic,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Generic), images.Generic)
}

func (f *Formatter) parseOutput(output string) error {
	var analysis *dependencyCheckEntities.Analysis

	index := strings.Index(output, "{")
	if index < 0 || output == "" {
		return nil
	}

	if err := json.Unmarshal([]byte(output[index:]), &analysis); err != nil {
		return err
	}

	f.parseToVulnerability(analysis)
	return nil
}

func (f *Formatter) parseToVulnerability(analysis *dependencyCheckEntities.Analysis) {
	for _, dependency := range analysis.Dependencies {
		vulnData := dependency.GetVulnerability()
		if vulnData == nil {
			continue
		}

		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(vulnData, dependency))
	}
}

func (f *Formatter) setVulnerabilityData(vulnData *dependencyCheckEntities.Vulnerability,
	dependency *dependencyCheckEntities.Dependency) *vulnerability.Vulnerability {
	vuln := f.getDefaultVulnerabilitySeverity()
	vuln.Severity = vulnData.GetSeverity()
	vuln.Details = vulnData.Description
	vuln.Code = f.GetCodeWithMaxCharacters(dependency.FileName, 0)
	vuln.File = f.RemoveSrcFolderFromPath(dependency.GetFile())
	return vulnhash.Bind(vuln)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.OwaspDependencyCheck
	vulnerabilitySeverity.Language = languages.Generic
	return vulnerabilitySeverity
}
