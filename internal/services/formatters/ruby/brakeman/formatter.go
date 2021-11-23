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

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec/internal/enums/images"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	errorsEnums "github.com/ZupIT/horusec/internal/enums/errors"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/ruby/brakeman/entities"
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

	output, err := f.startBrakeman(projectSubPath)
	f.SetAnalysisError(err, tools.Brakeman, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Brakeman, languages.Ruby)
}

func (f *Formatter) startBrakeman(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Brakeman, languages.Ruby)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}

	return output, f.parseOutput(output, projectSubPath)
}

func (f *Formatter) parseOutput(containerOutput, projectSubPath string) error {
	if containerOutput == "" {
		return nil
	}

	brakemanOutput, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}

	for _, warning := range brakemanOutput.Warnings {
		value := warning
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(&value, projectSubPath))
	}

	return nil
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output entities.Output, err error) {
	if f.isNotFoundRailsProject(containerOutput) {
		return entities.Output{}, errorsEnums.ErrNotFoundRailsProject
	}

	err = json.Unmarshal([]byte(containerOutput), &output)
	return output, err
}

func (f *Formatter) setVulnerabilityData(output *entities.Warning, projectSubPath string) *vulnerability.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = output.GetSeverity()
	data.Confidence = output.GetConfidence()
	data.Details = output.GetDetails()
	data.Line = output.GetLine()
	data.File = f.GetFilepathFromFilename(output.File, projectSubPath)
	data.Code = f.GetCodeWithMaxCharacters(output.Code, 0)
	data = vulnhash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.Brakeman
	vulnerabilitySeverity.Language = languages.Ruby
	return vulnerabilitySeverity
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.Brakeman),
		Language: languages.Ruby,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.Ruby), images.Ruby)
}

func (f *Formatter) isNotFoundRailsProject(output string) bool {
	const DefaultOutputMaxCharacters = 45
	lowerOutput := strings.ToLower(output)
	notFoundError := strings.ToLower("Please supply the path to a Rails application")
	if len(lowerOutput) >= DefaultOutputMaxCharacters {
		return strings.Contains(lowerOutput[:45], notFoundError)
	}
	return false
}
