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

package mixaudit

import (
	"encoding/json"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/elixir/mixaudit/entities"
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
	if f.ToolIsToIgnore(tools.MixAudit) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.MixAudit.ToString())
		return
	}

	f.SetAnalysisError(f.startMixAudit(projectSubPath), tools.MixAudit, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.MixAudit)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startMixAudit(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.MixAudit)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.GetConfigCMDByFileExtension(projectSubPath, ImageCmd, "mix.lock", tools.MixAudit),
		Language: languages.Elixir,
	}

	return analysisData.SetData(f.GetToolsConfig()[tools.MixAudit].ImagePath, ImageName, ImageTag)
}

func (f *Formatter) parseOutput(output string) error {
	var result entities.Result

	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return err
	}

	for index := range result.Vulnerabilities {
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(result.Vulnerabilities, index))
	}

	return nil
}

func (f *Formatter) setVulnerabilityData(vulnerabilities []entities.Vulnerability, index int) *horusec.Vulnerability {
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Severity = severity.High
	vulnerability.Details = vulnerabilities[index].GetDetails()
	vulnerability.Code = f.GetCodeWithMaxCharacters(vulnerabilities[index].Advisory.Package, 0)
	vulnerability.File = f.RemoveSrcFolderFromPath(vulnerabilities[index].Dependency.Lockfile)
	vulnerability = hash.Bind(vulnerability)
	return f.SetCommitAuthor(vulnerability)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.MixAudit
	vulnerabilitySeverity.Language = languages.Elixir
	return vulnerabilitySeverity
}
