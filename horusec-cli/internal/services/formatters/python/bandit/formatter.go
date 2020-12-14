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

package bandit

import (
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/python"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	jsonUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/json"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
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
	if f.ToolIsToIgnore(tools.Bandit) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.Bandit.ToString(), logger.DebugLevel)
		return
	}
	err := f.startBanditAnalysis(projectSubPath)
	f.LogAnalysisError(err, tools.Bandit, projectSubPath)
	f.SetLanguageIsFinished()
}

func (f *Formatter) startBanditAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Bandit)

	output, err := f.ExecuteContainer(f.getAnalysisData(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.parseOutput(output)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Bandit)
	return nil
}

func (f *Formatter) getAnalysisData(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.Bandit),
		Language: languages.Python,
	}
}

func (f *Formatter) parseOutput(output string) {
	if output == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty,
			logger.DebugLevel, map[string]interface{}{"tool": tools.Bandit.ToString()})
		return
	}

	banditOutput, err := f.parseOutputToBanditOutput(output)
	if err != nil {
		return
	}

	f.setBanditOutPutInHorusecAnalysis(banditOutput.Results)
}

func (f *Formatter) parseOutputToBanditOutput(output string) (banditOutput python.BanditOutput, err error) {
	err = jsonUtils.ConvertStringToOutput(output, &banditOutput)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.Bandit, output), err, logger.ErrorLevel)
	return banditOutput, err
}

func (f *Formatter) setBanditOutPutInHorusecAnalysis(issues []python.BanditResult) {
	totalInformation := 0
	for index := range issues {
		if f.notSkipVulnerabilityBecauseIsInformation(issues, index) {
			vulnerability := f.setupVulnerabilitiesSeveritiesBandit(issues, index)
			f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
				horusec.AnalysisVulnerabilities{Vulnerability: *vulnerability})
		} else {
			totalInformation++
		}
	}
	if totalInformation > 0 {
		logger.LogWarnWithLevel(
			strings.ReplaceAll(messages.MsgWarnBanditFoundInformative, "{{0}}", strconv.Itoa(totalInformation)),
			logger.WarnLevel)
	}
}

func (f *Formatter) setupVulnerabilitiesSeveritiesBandit(
	issues []python.BanditResult, index int) *horusec.Vulnerability {
	vulnerabilitySeverity := f.getDefaultVulnerabilitySeverity()
	vulnerabilitySeverity.Severity = issues[index].IssueSeverity
	vulnerabilitySeverity.Details = issues[index].IssueText
	vulnerabilitySeverity.Code = f.GetCodeWithMaxCharacters(issues[index].Code, 0)
	vulnerabilitySeverity.Line = strconv.Itoa(issues[index].LineNumber)
	vulnerabilitySeverity.Confidence = issues[index].IssueConfidence
	vulnerabilitySeverity.File = issues[index].GetFile()

	// Set vulnerabilitySeverity.VulnHash value
	vulnerabilitySeverity = vulnhash.Bind(vulnerabilitySeverity)

	return f.setCommitAuthor(vulnerabilitySeverity)
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
	vulnerabilitySeverity.Language = languages.Python
	vulnerabilitySeverity.SecurityTool = tools.Bandit
	vulnerabilitySeverity.Column = "0"
	return vulnerabilitySeverity
}

func (f *Formatter) notSkipVulnerabilityBecauseIsInformation(issues []python.BanditResult, index int) bool {
	skipAssertDetected := "Use of assert detected. " +
		"The enclosed code will be removed when compiling to optimized byte code."
	details := issues[index].IssueText
	return !strings.Contains(strings.ToLower(details), strings.ToLower(skipAssertDetected))
}
