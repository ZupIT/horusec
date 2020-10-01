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

	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/leaks"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	utilsHorusec "github.com/ZupIT/horusec/development-kit/pkg/utils/horusec"
	jsonUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/json"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	vulnhash "github.com/ZupIT/horusec/horusec-cli/internal/utils/vuln_hash"
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
	err := f.startGitLeaksAnalysis(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.GitLeaks, projectSubPath)
}

func (f *Formatter) startGitLeaksAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.GitLeaks)

	output, err := f.ExecuteContainer(f.gitLeaksImageTagCmd(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.GitLeaks)
	return f.formatOutputGitLeaks(output)
}

func (f *Formatter) formatOutputGitLeaks(output string) error {
	if output == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty, logger.DebugLevel,
			map[string]interface{}{"tool": tools.GitLeaks.ToString()})
		f.setGitLeaksOutPutInHorusecAnalysis([]leaks.Issue{})
		return nil
	}
	issues, err := f.parseOutputToIssues(output)
	if err != nil {
		return err
	}
	f.setGitLeaksOutPutInHorusecAnalysis(issues)
	return nil
}

func (f *Formatter) parseOutputToIssues(output string) ([]leaks.Issue, error) {
	var issues []leaks.Issue
	err := jsonUtils.ConvertStringToOutput(output, &issues)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.GitLeaks, output), err, logger.ErrorLevel)
	return issues, err
}

func (f *Formatter) setGitLeaksOutPutInHorusecAnalysis(issues []leaks.Issue) {
	for key := range issues {
		vulnerability := f.setupVulnerabilitiesSeveritiesGitLeaks(&issues[key])
		f.factoryAddVulnerabilityBySeverityGitLeaks(vulnerability)
	}
}

func (f *Formatter) setupVulnerabilitiesSeveritiesGitLeaks(issue *leaks.Issue) (
	vulnerabilitySeverity *horusec.Vulnerability) {
	vulnerabilitySeverity = f.getDefaultSeverity()
	vulnerabilitySeverity.Severity = utilsHorusec.GetSeverityOrNoSec(severity.High, issue.Line)
	vulnerabilitySeverity.Details = issue.Rule
	vulnerabilitySeverity.Code = f.GetCodeWithMaxCharacters(issue.Line, 0)
	vulnerabilitySeverity.File = issue.File

	// Set vulnerabilitySeverity.VulnHash value
	vulnerabilitySeverity = vulnhash.Bind(vulnerabilitySeverity)

	return f.setCommitAuthor(vulnerabilitySeverity, issue)
}

func (f *Formatter) factoryAddVulnerabilityBySeverityGitLeaks(vulnerability *horusec.Vulnerability) {
	f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities, horusec.AnalysisVulnerabilities{
		Vulnerability: *vulnerability,
	})
}

func (f *Formatter) setCommitAuthor(vulnerability *horusec.Vulnerability, issue *leaks.Issue) *horusec.Vulnerability {
	vulnerability.CommitAuthor = issue.Author
	vulnerability.CommitMessage = strings.ReplaceAll(issue.CommitMessage, "\n", "")
	vulnerability.CommitEmail = issue.Email
	vulnerability.CommitDate = issue.Date
	vulnerability.CommitHash = issue.Commit

	return vulnerability
}

func (f *Formatter) gitLeaksImageTagCmd(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath),
		Language: languages.Leaks,
	}
}

func (f *Formatter) getDefaultSeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.Language = languages.Leaks
	vulnerabilitySeverity.SecurityTool = tools.GitLeaks
	return vulnerabilitySeverity
}
