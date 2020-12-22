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

package flawfinder

import (
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	flawfinderEntities "github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/c/flawfinder/entities"
	"github.com/gocarina/gocsv"
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
	if f.ToolIsToIgnore(tools.Flawfinder) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.Flawfinder.ToString(), logger.DebugLevel)
		return
	}

	f.SetAnalysisError(f.startFlawfinder(projectSubPath), tools.Flawfinder, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Flawfinder)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startFlawfinder(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Flawfinder)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.Flawfinder),
		Language: languages.C,
	}

	return analysisData.SetFullImagePath(f.GetToolsConfig()[tools.Flawfinder].ImagePath, ImageName, ImageTag)
}

func (f *Formatter) parseOutput(output string) error {
	var results []flawfinderEntities.Result

	if err := gocsv.UnmarshalString(output, &results); err != nil {
		return err
	}

	for index := range results {
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(results, index))
	}

	return nil
}

func (f *Formatter) setVulnerabilityData(results []flawfinderEntities.Result, index int) *horusec.Vulnerability {
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Severity = results[index].GetSeverity()
	vulnerability.Details = results[index].GetDetails()
	vulnerability.Line = results[index].Line
	vulnerability.Column = results[index].Column
	vulnerability.Code = f.GetCodeWithMaxCharacters(results[index].Context, 0)
	vulnerability.File = results[index].GetFilename()
	vulnerability = hash.Bind(vulnerability)
	return f.SetCommitAuthor(vulnerability)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.Flawfinder
	vulnerabilitySeverity.Language = languages.C
	return vulnerabilitySeverity
}
