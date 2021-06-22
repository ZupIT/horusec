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

	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec/internal/enums/images"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/elixir/mixaudit/entities"
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
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.MixAudit, languages.Elixir)
}

func (f *Formatter) startMixAudit(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.MixAudit, languages.Elixir)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.GetConfigCMDByFileExtension(projectSubPath, CMD, "mix.lock", tools.MixAudit),
		Language: languages.Elixir,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.Elixir), images.Elixir)
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

func (f *Formatter) setVulnerabilityData(
	vulnerabilities []entities.Vulnerability, index int) *vulnerability.Vulnerability {
	vuln := f.getDefaultVulnerabilitySeverity()
	vuln.Severity = severities.High
	vuln.Details = vulnerabilities[index].GetDetails()
	vuln.Code = f.GetCodeWithMaxCharacters(vulnerabilities[index].Advisory.Package, 0)
	vuln.File = f.RemoveSrcFolderFromPath(vulnerabilities[index].Dependency.Lockfile)
	vuln = vulnhash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.MixAudit
	vulnerabilitySeverity.Language = languages.Elixir
	return vulnerabilitySeverity
}
