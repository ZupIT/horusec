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

package scs

import (
	"encoding/json"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	errorsEnums "github.com/ZupIT/horusec/internal/enums/errors"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/scs/entities"
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
	if f.ToolIsToIgnore(tools.SecurityCodeScan) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.SecurityCodeScan.ToString())
		return
	}

	f.SetAnalysisError(f.startSecurityCodeScan(projectSubPath), tools.SecurityCodeScan, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.SecurityCodeScan)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startSecurityCodeScan(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.SecurityCodeScan)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	if errSolution := f.verifyIsSolutionError(output, err); errSolution != nil {
		return errSolution
	}

	f.parseOutput(output)
	return nil
}

func (f *Formatter) parseOutput(output string) {
	for _, scsResult := range f.newScsResultArrayFromOutput(output) {
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilitySeverityData(scsResult))
	}
}

func (f *Formatter) newScsResultArrayFromOutput(dockerOutput string) (outputs []entities.ScsResult) {
	for _, output := range f.splitSCSContainerOutput(dockerOutput) {
		if output == "" {
			continue
		}

		if result, err := f.parseStringToStruct(output); err == nil && result.IsValid() {
			outputs = append(outputs, result)
		}
	}

	return f.removeDuplicatedOutputs(outputs)
}

func (f *Formatter) splitSCSContainerOutput(output string) []string {
	return strings.SplitAfter(output, "}")
}

func (f *Formatter) parseStringToStruct(output string) (scsResult entities.ScsResult, err error) {
	err = json.Unmarshal([]byte(output), &scsResult)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.SecurityCodeScan, output), err)
	return scsResult, err
}

func (f *Formatter) removeDuplicatedOutputs(scsResults []entities.ScsResult) []entities.ScsResult {
	return scsResults[0 : len(scsResults)/2]
}

func (f *Formatter) setVulnerabilitySeverityData(scsResult entities.ScsResult) *vulnerability.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = scsResult.GetSeverity()
	data.Details = f.removeCsprojPathFromDetails(scsResult.IssueText)
	data.Line = scsResult.GetLine()
	data.Column = scsResult.GetColumn()
	data.File = f.GetFilepathFromFilename(f.RemoveSrcFolderFromPath(scsResult.GetFilename()))
	data = vulnhash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.SecurityCodeScan
	vulnerabilitySeverity.Language = languages.CSharp
	return vulnerabilitySeverity
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD: f.AddWorkDirInCmd(CMD, file.GetSubPathByExtension(
			f.GetConfigProjectPath(), projectSubPath, "*.sln"), tools.SecurityCodeScan),
		Language: languages.CSharp,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.CSharp), images.Csharp)
}

func (f *Formatter) verifyIsSolutionError(output string, err error) error {
	if strings.Contains(output, "Specify a project or solution file") {
		msg := f.GetAnalysisIDErrorMessage(tools.SecurityCodeScan, output)
		logger.LogErrorWithLevel(msg, errorsEnums.ErrSolutionNotFound)
		return errorsEnums.ErrSolutionNotFound
	}

	return err
}

func (f *Formatter) removeCsprojPathFromDetails(details string) string {
	index := strings.Index(details, "[/src/")
	if details == "" || index <= 0 {
		return details
	}

	return details[:index]
}
