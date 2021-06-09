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
	"encoding/json"
	"errors"
	"strings"

	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec/internal/enums/images"

	"github.com/ZupIT/horusec/internal/services/formatters/leaks/gitleaks/entities"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
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
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.GitLeaks, languages.Leaks)
}

func (f *Formatter) startGitLeaks(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.GitLeaks, languages.Leaks)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.formatOutputGitLeaks(output)
}

func (f *Formatter) formatOutputGitLeaks(output string) error {
	if output == "" || (len(output) >= 4 && output[:4] == "null") {
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
	err := json.Unmarshal([]byte(output), &issues)
	if err != nil && strings.Contains(err.Error(), "invalid character") {
		err = errors.New(output)
	}
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.GitLeaks, output), err)
	return issues, err
}

func (f *Formatter) setGitLeaksOutPutInHorusecAnalysis(issues []entities.Issue) {
	for key := range issues {
		vuln := f.setupVulnerabilitiesSeveritiesGitLeaks(&issues[key])
		f.AddNewVulnerabilityIntoAnalysis(vuln)
	}
}

func (f *Formatter) setupVulnerabilitiesSeveritiesGitLeaks(issue *entities.Issue) (
	vulnerabilitySeverity *vulnerability.Vulnerability) {
	vulnerabilitySeverity = f.getDefaultSeverity()
	vulnerabilitySeverity.Severity = severities.Critical
	vulnerabilitySeverity.Details = issue.Rule
	vulnerabilitySeverity.Code = f.GetCodeWithMaxCharacters(issue.Line, 0)
	vulnerabilitySeverity.File = issue.File
	vulnerabilitySeverity = vulnhash.Bind(vulnerabilitySeverity)
	return f.setCommitAuthor(vulnerabilitySeverity, issue)
}

func (f *Formatter) setCommitAuthor(vuln *vulnerability.Vulnerability,
	issue *entities.Issue) *vulnerability.Vulnerability {
	vuln.CommitAuthor = issue.Author
	vuln.CommitMessage = strings.ReplaceAll(issue.CommitMessage, "\n", "")
	vuln.CommitEmail = issue.Email
	vuln.CommitDate = issue.Date
	vuln.CommitHash = issue.Commit
	return vuln
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.GitLeaks),
		Language: languages.Leaks,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.Leaks), images.Leaks)
}

func (f *Formatter) getDefaultSeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.Language = languages.Leaks
	vulnerabilitySeverity.SecurityTool = tools.GitLeaks
	return vulnerabilitySeverity
}
