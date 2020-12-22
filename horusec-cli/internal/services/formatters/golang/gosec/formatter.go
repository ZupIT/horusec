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

package gosec

import (
	"strconv"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	jsonUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/json"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/golang/gosec/entities"
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
	if f.ToolIsToIgnore(tools.GoSec) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.GoSec.ToString(), logger.DebugLevel)
		return
	}

	f.SetAnalysisError(f.startGoSec(projectSubPath), tools.GoSec, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.GoSec)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startGoSec(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.GoSec)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	f.processOutput(output)
	return nil
}

func (f *Formatter) processOutput(output string) {
	if output == "" {
		logger.LogDebugWithLevel(
			messages.MsgDebugOutputEmpty, logger.DebugLevel, map[string]interface{}{"tool": tools.GoSec.ToString()})
		return
	}

	golangOutput, err := f.parseOutputToGoOutput(output)
	if err != nil {
		return
	}

	f.setGoSecOutPutInHorusecAnalysis(golangOutput)
}

func (f *Formatter) parseOutputToGoOutput(output string) (golangOutput entities.Output, err error) {
	err = jsonUtils.ConvertStringToOutput(output, &golangOutput)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.GoSec, output), err, logger.ErrorLevel)
	return golangOutput, err
}

func (f *Formatter) setGoSecOutPutInHorusecAnalysis(golangOutput entities.Output) {
	for _, value := range golangOutput.Issues {
		issue := value
		vulnerability := f.setupVulnerabilitiesSeveritiesGoSec(&issue)
		f.AddNewVulnerabilityIntoAnalysis(vulnerability)
	}
}

func (f *Formatter) setupVulnerabilitiesSeveritiesGoSec(issue *entities.Issue) *horusec.Vulnerability {
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Severity = issue.Severity
	vulnerability.Details = issue.Details
	vulnerability.Code = f.getCode(issue.Code, issue.Column)
	vulnerability.Line = issue.Line
	vulnerability.Column = issue.Column
	vulnerability.Confidence = issue.Confidence
	vulnerability.File = f.RemoveSrcFolderFromPath(issue.File)
	vulnerability = hash.Bind(vulnerability)
	return f.SetCommitAuthor(vulnerability)
}

func (f *Formatter) getCode(code, column string) string {
	columnNumber, _ := strconv.Atoi(column)
	return f.GetCodeWithMaxCharacters(code, columnNumber)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.Language = languages.Go
	vulnerabilitySeverity.SecurityTool = tools.GoSec
	return vulnerabilitySeverity
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.GoSec),
		Language: languages.Go,
	}

	return analysisData.SetFullImagePath(f.GetToolsConfig()[tools.GoSec].ImagePath, ImageName, ImageTag)
}
