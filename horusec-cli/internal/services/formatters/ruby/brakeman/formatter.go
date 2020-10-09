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

package brakeman

import (
	"encoding/json"
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/ruby"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	errorsEnums "github.com/ZupIT/horusec/horusec-cli/internal/enums/errors"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
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
	err := f.startBrakemanAnalysis(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.Brakeman, projectSubPath)
}

func (f *Formatter) startBrakemanAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Brakeman)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Brakeman)
	return f.parseOutput(output)
}

func (f *Formatter) parseOutput(containerOutput string) error {
	if containerOutput == "" {
		return nil
	}
	outputs, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}
	for _, warning := range outputs.Warnings {
		value := warning
		f.setAnalysisResults(f.setVulnerabilityData(&value))
	}
	return nil
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output ruby.Output, err error) {
	if f.isNotFoundRailsProject(containerOutput) {
		f.SetAnalysisError(errorsEnums.ErrNotFoundRailsProject)
		return ruby.Output{}, errorsEnums.ErrNotFoundRailsProject
	}
	err = json.Unmarshal([]byte(containerOutput), &output)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.Brakeman, containerOutput),
		err, logger.ErrorLevel)
	return output, err
}

func (f *Formatter) setVulnerabilityData(output *ruby.Warning) *horusec.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = output.GetSeverity()
	data.Confidence = output.GetSeverity().ToString()
	data.Details = output.GetDetails()
	data.Line = output.GetLine()
	data.File = output.File
	data.Code = f.GetCodeWithMaxCharacters(output.Code, 0)

	// Set data.VulnHash value
	data = vulnhash.Bind(data)

	return f.setCommitAuthor(data)
}

func (f *Formatter) setCommitAuthor(vulnerability *horusec.Vulnerability) *horusec.Vulnerability {
	commitAuthor := f.GetCommitAuthor(vulnerability.Line, vulnerability.File)

	vulnerability.CommitAuthor = commitAuthor.Author
	vulnerability.CommitHash = commitAuthor.CommitHash
	vulnerability.CommitDate = commitAuthor.Date
	vulnerability.CommitEmail = commitAuthor.Email
	vulnerability.CommitMessage = commitAuthor.Message

	return vulnerability
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.Brakeman
	vulnerabilitySeverity.Language = languages.Ruby
	return vulnerabilitySeverity
}

func (f *Formatter) setAnalysisResults(vulnerability *horusec.Vulnerability) {
	f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
		horusec.AnalysisVulnerabilities{
			Vulnerability: *vulnerability,
		})
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.Brakeman),
		Language: languages.Ruby,
	}
}

func (f *Formatter) isNotFoundRailsProject(output string) bool {
	lowerOutput := strings.ToLower(output)
	notFoundError := strings.ToLower("Please supply the path to a Rails application")
	if len(lowerOutput) >= 45 {
		return strings.Contains(lowerOutput[:45], notFoundError)
	}
	return false
}
