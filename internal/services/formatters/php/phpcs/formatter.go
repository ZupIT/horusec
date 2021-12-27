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

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/php/phpcs/entities"
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
	if f.ToolIsToIgnore(tools.PhpCS) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.PhpCS.ToString())
		return
	}

	output, err := f.startPhpCs(projectSubPath)
	f.SetAnalysisError(err, tools.PhpCS, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.PhpCS, languages.PHP)
}

func (f *Formatter) startPhpCs(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.PhpCS, languages.PHP)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}

	return output, f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.PhpCS),
		Language: languages.PHP,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.PHP), images.PHP)
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

func (f *Formatter) setVulnerabilityData(filepath string, result entities.Message) *vulnerability.Vulnerability {
	vuln := f.getDefaultVulnerabilitySeverity()
	vuln.Severity = severities.Unknown
	vuln.Details = result.Message
	vuln.Line = result.GetLine()
	vuln.Column = result.GetColumn()
	vuln.File = f.RemoveSrcFolderFromPath(filepath)
	vuln = vulnhash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
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
