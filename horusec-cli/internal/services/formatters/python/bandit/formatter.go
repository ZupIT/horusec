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
	"strconv"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	jsonUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/json"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/python/bandit/entities"
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
	if f.ToolIsToIgnore(tools.Bandit) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Bandit.ToString())
		return
	}

	f.SetAnalysisError(f.startBandit(projectSubPath), tools.Bandit, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Bandit)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startBandit(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Bandit)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	f.parseOutput(output)
	return nil
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.Bandit),
		Language: languages.Python,
	}

	return analysisData.SetData(f.GetToolsConfig()[tools.Bandit].ImagePath, ImageName, ImageTag)
}

func (f *Formatter) parseOutput(output string) {
	if output == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty,
			map[string]interface{}{"tool": tools.Bandit.ToString()})
		return
	}

	banditOutput, err := f.parseOutputToBanditOutput(output)
	if err != nil {
		return
	}

	f.setBanditOutPutInHorusecAnalysis(banditOutput.Results)
}

func (f *Formatter) parseOutputToBanditOutput(output string) (banditOutput entities.BanditOutput, err error) {
	err = jsonUtils.ConvertStringToOutput(output, &banditOutput)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.Bandit, output), err)
	return banditOutput, err
}

func (f *Formatter) setBanditOutPutInHorusecAnalysis(issues []entities.Result) {
	totalInformation := 0
	for index := range issues {
		if f.notSkipVulnerabilityBecauseIsInformation(issues, index) {
			f.AddNewVulnerabilityIntoAnalysis(f.setupVulnerabilitiesSeveritiesBandit(issues, index))
		} else {
			totalInformation++
		}
	}
	if totalInformation > 0 {
		logger.LogWarnWithLevel(
			strings.ReplaceAll(messages.MsgWarnBanditFoundInformative, "{{0}}", strconv.Itoa(totalInformation)))
	}
}

func (f *Formatter) setupVulnerabilitiesSeveritiesBandit(
	issues []entities.Result, index int) *horusec.Vulnerability {
	vulnerabilitySeverity := f.getDefaultVulnerabilitySeverity()
	vulnerabilitySeverity.Severity = issues[index].IssueSeverity
	vulnerabilitySeverity.Details = issues[index].IssueText
	vulnerabilitySeverity.Code = f.GetCodeWithMaxCharacters(issues[index].Code, 0)
	vulnerabilitySeverity.Line = strconv.Itoa(issues[index].LineNumber)
	vulnerabilitySeverity.Confidence = issues[index].IssueConfidence
	vulnerabilitySeverity.File = issues[index].GetFile()
	vulnerabilitySeverity = hash.Bind(vulnerabilitySeverity)
	return f.SetCommitAuthor(vulnerabilitySeverity)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.Language = languages.Python
	vulnerabilitySeverity.SecurityTool = tools.Bandit
	vulnerabilitySeverity.Column = "0"
	return vulnerabilitySeverity
}

func (f *Formatter) notSkipVulnerabilityBecauseIsInformation(issues []entities.Result, index int) bool {
	skipAssertDetected := "Use of assert detected. " +
		"The enclosed code will be removed when compiling to optimized byte code."
	details := issues[index].IssueText
	return !strings.Contains(strings.ToLower(details), strings.ToLower(skipAssertDetected))
}
