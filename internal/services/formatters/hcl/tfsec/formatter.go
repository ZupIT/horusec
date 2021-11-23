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
	"fmt"
	"strings"

	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec/internal/enums/images"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/hcl/tfsec/entities"
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

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.TfSec),
		Language: languages.HCL,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.HCL), images.HCL)
}

func (f *Formatter) parseOutput(output string) error {
	var vulnerabilities *entities.Vulnerabilities

	if err := json.Unmarshal([]byte(output), &vulnerabilities); err != nil {
		if !strings.Contains(output, "panic") {
			return fmt.Errorf("{HORUSEC_CLI} Error %s", output)
		}

		return err
	}

	for index := range vulnerabilities.Results {
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(index, vulnerabilities.Results))
	}

	return nil
}

func (f *Formatter) setVulnerabilityData(index int, results []entities.Result) *vulnerability.Vulnerability {
	vuln := f.getDefaultVulnerabilityData()
	vuln.Severity = results[index].GetSeverity()
	vuln.Details = results[index].GetDetails()
	vuln.Line = results[index].GetStartLine()
	vuln.Code = f.GetCodeWithMaxCharacters(results[index].GetCode(), 0)
	vuln.File = f.RemoveSrcFolderFromPath(results[index].GetFilename())
	vuln = vulnhash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}

func (f *Formatter) getDefaultVulnerabilityData() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.TfSec
	vulnerabilitySeverity.Language = languages.HCL
	return vulnerabilitySeverity
}
