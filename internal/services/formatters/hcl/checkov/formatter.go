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

package checkov

import (
	"bytes"
	"encoding/json"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/pborman/ansi"

	"github.com/ZupIT/horusec/internal/entities/docker"
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
	if f.ToolIsToIgnore(tools.Checkov) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Checkov.ToString())
		return
	}

	output, err := f.startCheckov(projectSubPath)
	f.SetAnalysisError(err, tools.Checkov, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Checkov, languages.HCL)
}

func (f *Formatter) startCheckov(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Checkov, languages.HCL)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}

	return output, f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *docker.AnalysisData {
	analysisData := &docker.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.Checkov),
		Language: languages.HCL,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.HCL), images.HCL)
}

func (f *Formatter) parseOutput(output string) error {
	var vuln *checkovVulnerability
	binary, _ := ansi.Strip([]byte(output))
	// For some reason checkov returns an empty list when no vulnerabilities are found
	// and an object if vulnerabitilies are found, this checks ignores result when we have no vulnerabilities
	if bytes.Equal(binary, checkovEmptyValue) {
		return nil
	}
	if err := json.Unmarshal(binary, &vuln); err != nil {
		return err
	}
	for _, check := range vuln.Results.FailedChecks {
		f.AddNewVulnerabilityIntoAnalysis(f.newVulnerability(check))
	}
	return nil
}

func (f *Formatter) newVulnerability(check *checkovCheck) *vulnerability.Vulnerability {
	vuln := &vulnerability.Vulnerability{
		SecurityTool: tools.Checkov,
		Language:     languages.HCL,
		Severity:     severities.Unknown,
		Details:      check.getDetails(),
		Line:         check.getStartLine(),
		Code:         f.GetCodeWithMaxCharacters(check.getCode(), 0),
		File:         f.RemoveSrcFolderFromPath(check.FileAbsPath),
	}
	return f.SetCommitAuthor(vulnhash.Bind(vuln))
}
