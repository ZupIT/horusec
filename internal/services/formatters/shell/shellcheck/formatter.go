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

package shellcheck

import (
	"encoding/json"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec/internal/enums/images"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/shell/shellcheck/entities"
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
	if f.ToolIsToIgnore(tools.ShellCheck) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.ShellCheck.ToString())
		return
	}

	f.SetAnalysisError(f.startShellCheck(projectSubPath), tools.ShellCheck, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.ShellCheck)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startShellCheck(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.ShellCheck)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) parseOutput(containerOutput string) error {
	if containerOutput == "" {
		return nil
	}
	shellCheckOutput, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}
	for _, fixes := range shellCheckOutput {
		value := fixes
		if !f.isIgnoredFix(value.Message) {
			f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(&value))
		}
	}

	return nil
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output []entities.Output, err error) {
	const NotFoundFiles = "**/*.sh: **/*.sh: openBinaryFile: does not exist (No such file or directory)"

	containerOutput = strings.ReplaceAll(containerOutput, NotFoundFiles, "")

	err = json.Unmarshal([]byte(containerOutput), &output)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.ShellCheck, containerOutput), err)
	return output, err
}

func (f *Formatter) setVulnerabilityData(output *entities.Output) *vulnerability.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = severities.Low
	data.Confidence = confidence.Low
	data.Details = output.Message
	data.Column = output.GetColumn()
	data.Line = output.GetLine()
	data.File = strings.ReplaceAll(output.File, "./", "")
	data = vulnhash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.ShellCheck
	vulnerabilitySeverity.Language = languages.Shell
	return vulnerabilitySeverity
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.ShellCheck),
		Language: languages.Shell,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.Shell), images.Shell)
}

func (f *Formatter) isIgnoredFix(message string) bool {
	const MessageNotIncludes = "Tips depend on target shell and yours is unknown"

	return strings.Contains(strings.ToLower(message), strings.ToLower(MessageNotIncludes))
}
