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

package gitleaks

import (
	"strings"

	"github.com/ZupIT/horusec/horusec-cli/internal/enums/images"

	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/leaks/gitleaks/entities"

	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
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
	if f.ToolIsToIgnore(tools.GitLeaks) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.GitLeaks.ToString())
		return
	}

	f.SetAnalysisError(f.startGitLeaks(projectSubPath), tools.GitLeaks, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.GitLeaks)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startGitLeaks(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.GitLeaks)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.formatOutputGitLeaks(output)
}

func (f *Formatter) formatOutputGitLeaks(output string) error {
	if output == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty,
			map[string]interface{}{"tool": tools.GitLeaks.ToString()})
		f.setGitLeaksOutPutInHorusecAnalysis([]entities.Issue{})
		return nil
	}

	issues, err := f.parseOutputToIssues(output)
	if err != nil {
		return err
	}

	f.setGitLeaksOutPutInHorusecAnalysis(issues)
	return nil
}

func (f *Formatter) parseOutputToIssues(output string) ([]entities.Issue, error) {
	var issues []entities.Issue
	err := jsonUtils.ConvertStringToOutput(output, &issues)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.GitLeaks, output), err)
	return issues, err
}

func (f *Formatter) setGitLeaksOutPutInHorusecAnalysis(issues []entities.Issue) {
	for key := range issues {
		vulnerability := f.setupVulnerabilitiesSeveritiesGitLeaks(&issues[key])
		f.AddNewVulnerabilityIntoAnalysis(vulnerability)
	}
}

func (f *Formatter) setupVulnerabilitiesSeveritiesGitLeaks(issue *entities.Issue) (
	vulnerabilitySeverity *horusec.Vulnerability) {
	vulnerabilitySeverity = f.getDefaultSeverity()
	vulnerabilitySeverity.Severity = severity.Unknown
	vulnerabilitySeverity.Details = issue.Rule
	vulnerabilitySeverity.Code = f.GetCodeWithMaxCharacters(issue.Line, 0)
	vulnerabilitySeverity.File = issue.File
	vulnerabilitySeverity = vulnhash.Bind(vulnerabilitySeverity)
	return f.setCommitAuthor(vulnerabilitySeverity, issue)
}

func (f *Formatter) setCommitAuthor(vulnerability *horusec.Vulnerability,
	issue *entities.Issue) *horusec.Vulnerability {
	vulnerability.CommitAuthor = issue.Author
	vulnerability.CommitMessage = strings.ReplaceAll(issue.CommitMessage, "\n", "")
	vulnerability.CommitEmail = issue.Email
	vulnerability.CommitDate = issue.Date
	vulnerability.CommitHash = issue.Commit
	return vulnerability
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.GitLeaks),
		Language: languages.Leaks,
	}

	return analysisData.SetData(f.GetToolsConfig()[tools.GitLeaks].ImagePath, images.Leaks)
}

func (f *Formatter) getDefaultSeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.Language = languages.Leaks
	vulnerabilitySeverity.SecurityTool = tools.GitLeaks
	return vulnerabilitySeverity
}
