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
	"fmt"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/dotnet"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	fileUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	errorsEnums "github.com/ZupIT/horusec/horusec-cli/internal/enums/errors"
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
	err := f.startSecurityCodeScanAnalysis(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.SecurityCodeScan, projectSubPath)
}

func (f *Formatter) startSecurityCodeScanAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.SecurityCodeScan)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err = f.verifyIsCsProjError(output, err); err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.parseOutput(output)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.SecurityCodeScan)
	return nil
}

func (f *Formatter) parseOutput(containerOutput string) {
	for _, value := range f.newContainerOutputFromString(containerOutput) {
		f.appendVulnerabilities(f.setVulnerabilitySeverityData(value))
	}
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (outputs []dotnet.Output) {
	for _, output := range f.splitSCSContainerOutput(containerOutput) {
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

func (f *Formatter) parseStringToStruct(output string) (containerOutput dotnet.Output, err error) {
	err = json.Unmarshal([]byte(output), &containerOutput)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.SecurityCodeScan, output), err, logger.ErrorLevel)
	return containerOutput, err
}

func (f *Formatter) removeDuplicatedOutputs(outputs []dotnet.Output) []dotnet.Output {
	return outputs[0 : len(outputs)/2]
}

func (f *Formatter) setVulnerabilitySeverityData(output dotnet.Output) *horusec.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = output.GetSeverity()
	data.Details = f.removeCsprojPathFromDetails(output.IssueText)
	data.Line = output.GetLine()
	data.Column = output.GetColumn()
	data.File = output.GetFilename()

	// Set data.VulnHash value
	data = vulnhash.Bind(data)

	return f.setCommitAuthor(data)
}

func (f *Formatter) setCommitAuthor(vulnerability *horusec.Vulnerability) *horusec.Vulnerability {
	commitAuthor := f.GetCommitAuthor(vulnerability.Line, f.getFilePathFromPackageName(vulnerability.File))

	vulnerability.CommitAuthor = commitAuthor.Author
	vulnerability.CommitHash = commitAuthor.CommitHash
	vulnerability.CommitDate = commitAuthor.Date
	vulnerability.CommitEmail = commitAuthor.Email
	vulnerability.CommitMessage = commitAuthor.Message

	return vulnerability
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.SecurityCodeScan
	vulnerabilitySeverity.Language = languages.DotNet

	return vulnerabilitySeverity
}

func (f *Formatter) appendVulnerabilities(vulnerability *horusec.Vulnerability) {
	f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
		horusec.AnalysisVulnerabilities{
			Vulnerability: *vulnerability,
		})
}

func (f *Formatter) getFilePathFromPackageName(filePath string) string {
	return fileUtil.GetPathIntoFilename(filePath,
		fmt.Sprintf("%s/.horusec/%s/", f.GetConfigProjectPath(), f.GetAnalysisID()))
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image: ImageName,
		Tag:   ImageTag,
		CMD: f.AddWorkDirInCmd(ImageCmd,
			fileUtil.GetSubPathByExtension(f.GetConfigProjectPath(), projectSubPath, "*.csproj")),
		Language: languages.DotNet,
	}
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
