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
	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/golang"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	jsonUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/json"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"strconv"
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
	if f.ToolIsToIgnore(tools.GoSec) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.GoSec.ToString(), logger.DebugLevel)
		return
	}
	err := f.startGoLangGoSecAnalysis(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.GoSec, projectSubPath)
}

func (f *Formatter) startGoLangGoSecAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.GoSec)

	output, err := f.ExecuteContainer(f.getAnalysisData(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.processOutput(output)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.GoSec)
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

func (f *Formatter) parseOutputToGoOutput(output string) (golangOutput golang.Output, err error) {
	err = jsonUtils.ConvertStringToOutput(output, &golangOutput)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.GoSec, output), err, logger.ErrorLevel)
	return golangOutput, err
}

func (f *Formatter) setGoSecOutPutInHorusecAnalysis(golangOutput golang.Output) {
	for _, value := range golangOutput.Issues {
		issue := value
		vulnerability := f.setupVulnerabilitiesSeveritiesGoSec(&issue)
		f.addVulnerabilityBySeverityGoSec(vulnerability)
	}
}

func (f *Formatter) setupVulnerabilitiesSeveritiesGoSec(issue *golang.Issue) *horusec.Vulnerability {
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Severity = issue.Severity
	vulnerability.Details = issue.Details
	vulnerability.Code = f.getCode(issue.Code, issue.Column)
	vulnerability.Line = issue.Line
	vulnerability.Column = issue.Column
	vulnerability.Confidence = issue.Confidence
	vulnerability.File = f.RemoveSrcFolderFromPath(issue.File)

	// Set vulnerabilitySeverity.VulnHash value
	vulnerability = vulnhash.Bind(vulnerability)

	return f.setCommitAuthor(vulnerability)
}

func (f *Formatter) getCode(code, column string) string {
	columnNumber, _ := strconv.Atoi(column)
	return f.GetCodeWithMaxCharacters(code, columnNumber)
}

func (f *Formatter) setCommitAuthor(vulnerability *horusec.Vulnerability) *horusec.Vulnerability {
	commitAuthor := f.GetCommitAuthor(vulnerability.Line, vulnerability.File)

	vulnerability.CommitAuthor = commitAuthor.Author
	vulnerability.CommitHash = commitAuthor.CommitHash
	vulnerability.CommitDate = commitAuthor.Date
	vulnerability.CommitEmail = commitAuthor.Email
	vulnerability.CommitMessage = commitAuthor.Message

	return vulnerability
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.Language = languages.Go
	vulnerabilitySeverity.SecurityTool = tools.GoSec
	return vulnerabilitySeverity
}

func (f *Formatter) addVulnerabilityBySeverityGoSec(vulnerability *horusec.Vulnerability) {
	f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
		horusec.AnalysisVulnerabilities{
			Vulnerability: *vulnerability,
		})
}

func (f *Formatter) getAnalysisData(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.GoSec),
		Language: languages.Go,
	}
}
