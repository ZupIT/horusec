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

package eslint

import (
	"fmt"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	jsonUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/json"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/javascript/eslint/entities"
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
	if f.ToolIsToIgnore(tools.Eslint) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Eslint.ToString())
		return
	}

	f.SetAnalysisError(f.startEsLint(projectSubPath), tools.Eslint, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Eslint)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startEsLint(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Eslint)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	f.processOutput(output)

	return nil
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.Eslint),
		Language: languages.Javascript,
	}

	return analysisData.SetFullImagePath(
		f.GetToolsConfig()[tools.Eslint].ImagePath, ImageRepository, ImageName, ImageTag)
}

func (f *Formatter) processOutput(output string) {
	if output == "" {
		logger.LogDebugWithLevel(
			messages.MsgDebugOutputEmpty, map[string]interface{}{"tool": tools.Eslint.ToString()})
		return
	}

	eslintOutput, err := f.parseOutput(output)
	if err != nil {
		return
	}

	f.concatOutputIntoAnalysisVulns(eslintOutput)
}

func (f *Formatter) parseOutput(output string) (eslintOutput *[]entities.Output, err error) {
	err = jsonUtils.ConvertStringToOutput(output, &eslintOutput)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.Eslint, output), err)
	return eslintOutput, err
}

func (f *Formatter) concatOutputIntoAnalysisVulns(output *[]entities.Output) {
	for _, file := range *output {
		for _, message := range *file.Messages {
			messagePointer := message
			vuln := f.parseOutputToVuln(file.FilePath, file.Source, &messagePointer)
			hash.Bind(vuln)
			f.SetCommitAuthor(vuln)
			f.AddNewVulnerabilityIntoAnalysis(vuln)
		}
	}
}

func (f *Formatter) parseOutputToVuln(filePath, source string, message *entities.Message) *horusec.Vulnerability {
	return &horusec.Vulnerability{
		File:         f.RemoveSrcFolderFromPath(filePath),
		Line:         fmt.Sprintf(`%d`, message.Line),
		Column:       fmt.Sprintf(`%d`, message.Column),
		Language:     languages.Javascript,
		SecurityTool: tools.Eslint,
		Details:      message.Message,
		Code:         f.getCode(source, message.Line, message.EndLine, message.Column),
		Severity:     severity.Low,
	}
}

func (f *Formatter) getCode(source string, line, endLine, column int) string {
	var result string
	startLine := line - 1
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		if i >= startLine && i <= endLine {
			result += line
		}

		if i > endLine {
			break
		}
	}

	return f.GetCodeWithMaxCharacters(result, column)
}
