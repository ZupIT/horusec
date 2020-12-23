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

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	fileUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	errorsEnums "github.com/ZupIT/horusec/horusec-cli/internal/enums/errors"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/csharp/scs/entities"
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
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.SecurityCodeScan.ToString(), logger.DebugLevel)
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

	if errCsproj := f.verifyIsCsProjError(output, err); errCsproj != nil {
		return errCsproj
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
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.SecurityCodeScan, output), err, logger.ErrorLevel)
	return scsResult, err
}

func (f *Formatter) removeDuplicatedOutputs(scsResults []entities.ScsResult) []entities.ScsResult {
	return scsResults[0 : len(scsResults)/2]
}

func (f *Formatter) setVulnerabilitySeverityData(scsResult entities.ScsResult) *horusec.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = scsResult.GetSeverity()
	data.Details = f.removeCsprojPathFromDetails(scsResult.IssueText)
	data.Line = scsResult.GetLine()
	data.Column = scsResult.GetColumn()
	data.File = f.GetFilepathFromFilename(scsResult.GetFilename())
	data = hash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.SecurityCodeScan
	vulnerabilitySeverity.Language = languages.CSharp
	return vulnerabilitySeverity
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD: f.AddWorkDirInCmd(ImageCmd, fileUtil.GetSubPathByExtension(
			f.GetConfigProjectPath(), projectSubPath, "*.csproj"), tools.SecurityCodeScan),
		Language: languages.CSharp,
	}

	return analysisData.SetFullImagePath(f.GetToolsConfig()[tools.SecurityCodeScan].ImagePath, ImageName, ImageTag)
}

func (f *Formatter) verifyIsCsProjError(output string, err error) error {
	if strings.Contains(output, "Could not find any project in") {
		msg := f.GetAnalysisIDErrorMessage(tools.SecurityCodeScan, output)
		logger.LogErrorWithLevel(msg, errorsEnums.ErrCsProjNotFound, logger.ErrorLevel)
		return errorsEnums.ErrCsProjNotFound
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
