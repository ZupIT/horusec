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
	"strconv"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
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

	output, err := f.startGitLeaks(projectSubPath)
	f.SetAnalysisError(err, tools.GitLeaks, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.GitLeaks, languages.Leaks)
}

func (f *Formatter) startGitLeaks(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.GitLeaks, languages.Leaks)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}

	if err := f.checkOutputErrors(output); err != nil {
		return output, err
	}

	return output, f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.GitLeaks),
		Language: languages.Leaks,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Leaks), images.Leaks)
}

func (f *Formatter) parseOutput(output string) error {
	issues := make([]*Issue, 0)

	if err := json.Unmarshal([]byte(output), &issues); err != nil {
		return err
	}

	if len(issues) == 0 {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty,
			map[string]interface{}{"tool": tools.GitLeaks.ToString()})
		return nil
	}

	f.forEachIssueCreateNewVuln(issues)

	return nil
}

func (f *Formatter) forEachIssueCreateNewVuln(issues []*Issue) {
	for _, issue := range issues {
		f.AddNewVulnerabilityIntoAnalysis(f.newVulnerability(issue))
	}
}

//nolint:funlen // necessary to be long
func (f *Formatter) newVulnerability(issue *Issue) *vulnerability.Vulnerability {
	vuln := &vulnerability.Vulnerability{
		Language:      languages.Leaks,
		SecurityTool:  tools.GitLeaks,
		Severity:      severities.Critical,
		RuleID:        vulnhash.HashRuleID(issue.Description),
		Details:       issue.Description,
		Code:          f.GetCodeWithMaxCharacters(issue.Secret, 0),
		File:          issue.File,
		Line:          strconv.Itoa(issue.StartLine),
		Column:        strconv.Itoa(issue.StartColumn),
		CommitAuthor:  issue.Author,
		CommitMessage: f.GetCodeWithMaxCharacters(issue.Message, 0),
		CommitEmail:   issue.Email,
		CommitDate:    issue.Date,
		CommitHash:    issue.Commit,
	}

	return vulnhash.Bind(vuln)
}

func (f *Formatter) checkOutputErrors(output string) error {
	if strings.Contains(output, "fatal: not a git repository") ||
		strings.Contains(output, "fatal: cannot chdir to") {
		return errors.New(messages.MsgWarnPathIsInvalidGitRepository)
	}

	return nil
}
