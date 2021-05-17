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

	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/elixir/sobelow/entities"
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
		CMD:      f.GetConfigCMDByFileExtension(projectSubPath, CMD, "mix.lock", tools.Sobelow),
		Language: languages.Elixir,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.Elixir), images.Elixir)
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

	if !strings.Contains(output, "[+]\u001B[0m") {
		return nil
	}

	return &entities.Output{
		Title: strings.TrimSpace(output[indexFirstColon+1 : indexTrace]),
		File:  strings.TrimSpace(output[indexTrace+1 : indexLastColon]),
		Line:  strings.TrimSpace(output[indexLastColon+1:]),
	}
}

func (f *Formatter) setVulnerabilityData(output *entities.Output) *vulnerability.Vulnerability {
	vuln := f.getDefaultVulnerabilitySeverity()
	vuln.Details = output.Title
	vuln.File = f.GetFilepathFromFilename(output.File)
	vuln.Line = output.Line
	vuln = vulnhash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.Sobelow
	vulnerabilitySeverity.Language = languages.Elixir
	vulnerabilitySeverity.Severity = severities.Unknown
	return vulnerabilitySeverity
}
