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

package phpcs

import (
	"encoding/json"

	"github.com/ZupIT/horusec/horusec-cli/internal/enums/images"

	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/php/phpcs/entities"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
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
	if f.ToolIsToIgnore(tools.PhpCS) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.PhpCS.ToString())
		return
	}

	f.SetAnalysisError(f.startPhpCs(projectSubPath), tools.PhpCS, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.PhpCS)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startPhpCs(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.PhpCS)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.PhpCS),
		Language: languages.PHP,
	}

	return analysisData.SetData(f.GetToolsConfig()[tools.PhpCS].ImagePath, images.PHP)
}

func (f *Formatter) parseOutput(output string) error {
	var results map[string]interface{}

	if err := json.Unmarshal([]byte(output), &results); err != nil {
		return err
	}

	f.parseResults(results)
	return nil
}

func (f *Formatter) parseResults(results map[string]interface{}) {
	if results != nil {
		files := results["files"]
		for filepath, result := range files.(map[string]interface{}) {
			f.parseMessages(filepath, result)
		}
	}
}

func (f *Formatter) parseMessages(filepath string, result interface{}) {
	for _, message := range f.parseToResult(result).Messages {
		if message.IsValidMessage() {
			f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(filepath, message))
		}
	}
}

func (f *Formatter) setVulnerabilityData(filepath string, result entities.Message) *horusec.Vulnerability {
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Severity = severity.Unknown
	vulnerability.Details = result.Message
	vulnerability.Line = result.GetLine()
	vulnerability.Column = result.GetColumn()
	vulnerability.File = f.RemoveSrcFolderFromPath(filepath)
	vulnerability = vulnhash.Bind(vulnerability)
	return f.SetCommitAuthor(vulnerability)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.PhpCS
	vulnerabilitySeverity.Language = languages.PHP
	return vulnerabilitySeverity
}

func (f *Formatter) parseToResult(messageInterface interface{}) *entities.Result {
	var result *entities.Result

	bytes, _ := json.Marshal(messageInterface)
	_ = json.Unmarshal(bytes, &result)

	return result
}
