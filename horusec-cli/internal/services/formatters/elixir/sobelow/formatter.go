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

package sobelow

import (
	"errors"
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
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/elixir/sobelow/entities"
)

type Formatter struct {
	formatters.IService
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		service,
	}
}

const NotAPhoenixApplication = "this does not appear to be a Phoenix application. if this is an Umbrella application," +
	" each application should be scanned separately"

var ErrorNotAPhoenixApplication = errors.New(NotAPhoenixApplication)

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.Sobelow) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Sobelow.ToString())
		return
	}

	f.SetAnalysisError(f.startSobelow(projectSubPath), tools.Sobelow, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Sobelow)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startSobelow(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Sobelow)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		return err
	}

	if strings.Contains(output, NotAPhoenixApplication) {
		return ErrorNotAPhoenixApplication
	}

	return f.parseOutput(output)
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.Sobelow),
		Language: languages.Elixir,
	}

	return analysisData.SetFullImagePath(f.GetToolsConfig()[tools.Sobelow].ImagePath, ImageName, ImageTag)
}

func (f *Formatter) parseOutput(output string) error {
	const replaceDefaultMessage = "Checking Sobelow version..."
	output = strings.ReplaceAll(strings.ReplaceAll(output, replaceDefaultMessage, ""), "\r", "")

	for _, value := range strings.Split(output, "\n") {
		if value == "" {
			continue
		}

		if data := f.setOutputData(value); data != nil {
			f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(data))
		}
	}

	return nil
}

func (f *Formatter) setOutputData(output string) *entities.Output {
	indexFirstColon := strings.Index(output, ":")
	indexLastColon := strings.LastIndex(output, ":")
	indexTrace := strings.LastIndex(output, "-")

	if indexFirstColon == -1 || indexLastColon == -1 || indexTrace == -1 {
		return nil
	}

	return &entities.Output{
		Title: strings.TrimSpace(output[indexFirstColon+1 : indexTrace]),
		File:  strings.TrimSpace(output[indexTrace+1 : indexLastColon]),
		Line:  strings.TrimSpace(output[indexLastColon+1:]),
	}
}

func (f *Formatter) setVulnerabilityData(output *entities.Output) *horusec.Vulnerability {
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Details = output.Title
	vulnerability.File = output.File
	vulnerability.Line = output.Line
	vulnerability = hash.Bind(vulnerability)
	return f.SetCommitAuthor(vulnerability)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.Sobelow
	vulnerabilitySeverity.Language = languages.Elixir
	vulnerabilitySeverity.Severity = severity.High
	return vulnerabilitySeverity
}
