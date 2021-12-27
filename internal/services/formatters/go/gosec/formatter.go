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

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

// Formatter represents the Gosec formatter.
type Formatter struct {
	formatters.IService
}

// NewFormatter create a new gosec formatter.
func NewFormatter(service formatters.IService) *Formatter {
	return &Formatter{
		service,
	}
}

// StartAnalysis implements the formatters.IFormatter interface.
func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.GoSec) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.GoSec.ToString())
		return
	}

	output, err := f.startGoSec(projectSubPath)
	f.SetAnalysisError(err, tools.GoSec, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.GoSec, languages.Go)
}

func (f *Formatter) startGoSec(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.GoSec, languages.Go)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}

	return "", f.processOutput(output)
}

// nolint: funlen
func (f *Formatter) processOutput(output string) error {
	if output == "" {
		logger.LogDebugWithLevel(
			messages.MsgDebugOutputEmpty,
			map[string]interface{}{
				"tool": tools.GoSec,
			},
		)
		return nil
	}

	gosecOutput, err := f.parseOutputToGosecOutput(output)
	if err != nil {
		return err
	}

	f.addGosecOutputOnAnalysis(gosecOutput)
	return nil
}

func (f *Formatter) parseOutputToGosecOutput(output string) (gosecOutput output, err error) {
	err = json.Unmarshal([]byte(output), &gosecOutput)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.GoSec, output), err)
	return gosecOutput, err
}

func (f *Formatter) addGosecOutputOnAnalysis(gosecOutput output) {
	for idx := range gosecOutput.Issues {
		gosecIssue := gosecOutput.Issues[idx]
		f.AddNewVulnerabilityIntoAnalysis(f.newVulnerabilityFromIssue(&gosecIssue))
	}
}

func (f *Formatter) newVulnerabilityFromIssue(issue *issue) *vulnerability.Vulnerability {
	vuln := &vulnerability.Vulnerability{
		Language:     languages.Go,
		SecurityTool: tools.GoSec,
		Severity:     issue.Severity,
		Details:      issue.Details,
		Code:         f.getCode(issue.Code, issue.Column),
		Line:         issue.Line,
		Column:       issue.Column,
		Confidence:   issue.Confidence,
		File:         f.RemoveSrcFolderFromPath(issue.File),
	}
	return f.SetCommitAuthor(vulnhash.Bind(vuln))
}

func (f *Formatter) getCode(code, column string) string {
	columnNumber, _ := strconv.Atoi(column)
	return f.GetCodeWithMaxCharacters(code, columnNumber)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *docker.AnalysisData {
	analysisData := &docker.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.GoSec),
		Language: languages.Go,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Go), images.Go)
}
