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
	"encoding/json"
	"strconv"

	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec/internal/enums/images"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/go/gosec/entities"
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
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.GoSec.ToString())
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
			messages.MsgDebugOutputEmpty, map[string]interface{}{"tool": tools.GoSec.ToString()})
		return
	}

	golangOutput, err := f.parseOutputToGoOutput(output)
	if err != nil {
		return
	}

	f.setGoSecOutPutInHorusecAnalysis(golangOutput)
}

func (f *Formatter) parseOutputToGoOutput(output string) (golangOutput entities.Output, err error) {
	err = json.Unmarshal([]byte(output), &golangOutput)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.GoSec, output), err)
	return golangOutput, err
}

func (f *Formatter) setGoSecOutPutInHorusecAnalysis(golangOutput entities.Output) {
	for _, value := range golangOutput.Issues {
		issue := value
		vuln := f.setupVulnerabilitiesSeveritiesGoSec(&issue)
		f.AddNewVulnerabilityIntoAnalysis(vuln)
	}
}

func (f *Formatter) setupVulnerabilitiesSeveritiesGoSec(issue *entities.Issue) *vulnerability.Vulnerability {
	vuln := f.getDefaultVulnerabilitySeverity()
	vuln.Severity = issue.Severity
	vuln.Details = issue.Details
	vuln.Code = f.getCode(issue.Code, issue.Column)
	vuln.Line = issue.Line
	vuln.Column = issue.Column
	vuln.Confidence = issue.Confidence
	vuln.File = f.RemoveSrcFolderFromPath(issue.File)
	vuln = vulnhash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}

func (f *Formatter) getCode(code, column string) string {
	columnNumber, _ := strconv.Atoi(column)
	return f.GetCodeWithMaxCharacters(code, columnNumber)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.Language = languages.Go
	vulnerabilitySeverity.SecurityTool = tools.GoSec
	return vulnerabilitySeverity
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.GoSec),
		Language: languages.Go,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.Go), images.Go)
}
