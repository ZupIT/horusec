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
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	errorsEnums "github.com/ZupIT/horusec/horusec-cli/internal/enums/errors"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/ruby/brakeman/entities"
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
	if f.ToolIsToIgnore(tools.Brakeman) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Brakeman.ToString())
		return
	}

	f.SetAnalysisError(f.startBrakeman(projectSubPath), tools.Brakeman, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Brakeman)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startBrakeman(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Brakeman)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) parseOutput(containerOutput string) error {
	if containerOutput == "" {
		return nil
	}

	brakemanOutput, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}

	for _, warning := range brakemanOutput.Warnings {
		value := warning
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(&value))
	}

	return nil
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output entities.Output, err error) {
	if f.isNotFoundRailsProject(containerOutput) {
		return entities.Output{}, errorsEnums.ErrNotFoundRailsProject
	}

	err = json.Unmarshal([]byte(containerOutput), &output)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.Brakeman, containerOutput), err)
	return output, err
}

func (f *Formatter) setVulnerabilityData(output *entities.Warning) *horusec.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = output.GetSeverity()
	data.Confidence = output.GetSeverity().ToString()
	data.Details = output.GetDetails()
	data.Line = output.GetLine()
	data.File = output.File
	data.Code = f.GetCodeWithMaxCharacters(output.Code, 0)
	data = hash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.Brakeman
	vulnerabilitySeverity.Language = languages.Ruby
	return vulnerabilitySeverity
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.Brakeman),
		Language: languages.Ruby,
	}

	return analysisData.SetData(f.GetToolsConfig()[tools.Brakeman].ImagePath, ImageName, ImageTag)
}

func (f *Formatter) isNotFoundRailsProject(output string) bool {
	lowerOutput := strings.ToLower(output)
	notFoundError := strings.ToLower("Please supply the path to a Rails application")
	if len(lowerOutput) >= 45 {
		return strings.Contains(lowerOutput[:45], notFoundError)
	}
	return false
}
