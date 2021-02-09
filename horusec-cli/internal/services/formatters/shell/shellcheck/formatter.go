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

	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/shell/shellcheck/entities"
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

func (f *Formatter) setVulnerabilityData(output *entities.Output) *horusec.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = f.parseLevelToSeverity(output.Level)
	data.Confidence = confidence.Low.ToString()
	data.Details = output.Message
	data.Column = output.GetColumn()
	data.Line = output.GetLine()
	data.File = strings.ReplaceAll(output.File, "./", "")
	data = hash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.ShellCheck
	vulnerabilitySeverity.Language = languages.Shell
	return vulnerabilitySeverity
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.ShellCheck),
		Language: languages.Shell,
	}

	return analysisData.SetData(f.GetToolsConfig()[tools.ShellCheck].ImagePath, ImageName, ImageTag)
}

func (f *Formatter) isIgnoredFix(message string) bool {
	const MessageNotIncludes = "Tips depend on target shell and yours is unknown"

	return strings.Contains(strings.ToLower(message), strings.ToLower(MessageNotIncludes))
}

func (f *Formatter) parseLevelToSeverity(level string) severity.Severity {
	switch level {
	case "error":
		return severity.Low
	case "warning":
		return severity.Low
	default:
		return severity.Info
	}
}
