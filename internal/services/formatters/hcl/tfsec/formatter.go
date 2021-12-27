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

package tfsec

import (
	"encoding/json"
	"errors"
	"strings"

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

type Formatter struct {
	formatters.IService
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.TfSec) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.TfSec.ToString())
		return
	}

	output, err := f.startTfSec(projectSubPath)
	f.SetAnalysisError(err, tools.TfSec, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.TfSec, languages.HCL)
}

func (f *Formatter) startTfSec(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.TfSec, languages.HCL)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}

	return output, f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *docker.AnalysisData {
	analysisData := &docker.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.TfSec),
		Language: languages.HCL,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.HCL), images.HCL)
}

func (f *Formatter) parseOutput(output string) error {
	var vulnerabilities *tfsecVulnerabilities

	if err := json.Unmarshal([]byte(output), &vulnerabilities); err != nil {
		if !strings.Contains(output, "panic") {
			return errors.New(output)
		}
		return err
	}

	for index := range vulnerabilities.Results {
		f.AddNewVulnerabilityIntoAnalysis(f.newVulnerability(&vulnerabilities.Results[index]))
	}

	return nil
}

func (f *Formatter) newVulnerability(result *tfsecResult) *vulnerability.Vulnerability {
	vuln := &vulnerability.Vulnerability{
		SecurityTool: tools.TfSec,
		Language:     languages.HCL,
		Severity:     result.getSeverity(),
		Details:      result.getDetails(),
		Line:         result.getStartLine(),
		Code:         f.GetCodeWithMaxCharacters(result.getCode(), 0),
		File:         f.RemoveSrcFolderFromPath(result.getFilename()),
	}
	vuln = vulnhash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}
