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

package hcl

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/hcl/entities"
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
	if f.ToolIsToIgnore(tools.TfSec) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.TfSec.ToString(), logger.DebugLevel)
		return
	}

	f.SetAnalysisError(f.startTfSec(projectSubPath), tools.TfSec, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.TfSec)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startTfSec(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.TfSec)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.TfSec),
		Language: languages.HCL,
	}

	return analysisData.SetFullImagePath(f.GetToolsConfig()[tools.TfSec].ImagePath, ImageName, ImageTag)
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

func (f *Formatter) setVulnerabilityData(index int, results []entities.Result) *horusec.Vulnerability {
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Severity = severity.High
	vulnerability.Details = results[index].GetDetails()
	vulnerability.Line = results[index].GetStartLine()
	vulnerability.Code = f.GetCodeWithMaxCharacters(results[index].GetCode(), 0)
	vulnerability.File = f.RemoveSrcFolderFromPath(results[index].GetFilename())
	vulnerability = hash.Bind(vulnerability)
	return f.SetCommitAuthor(vulnerability)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.TfSec
	vulnerabilitySeverity.Language = languages.HCL
	return vulnerabilitySeverity
}
