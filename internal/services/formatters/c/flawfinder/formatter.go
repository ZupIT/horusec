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
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/gocarina/gocsv"

	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	flawfinderEntities "github.com/ZupIT/horusec/internal/services/formatters/c/flawfinder/entities"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
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
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Flawfinder.ToString())
		return
	}

	output, err := f.startFlawfinder(projectSubPath)
	f.SetAnalysisError(err, tools.Flawfinder, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Flawfinder, languages.C)
}

func (f *Formatter) startFlawfinder(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Flawfinder, languages.C)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		return output, err
	}

	return output, f.parseOutput(output)
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.Flawfinder),
		Language: languages.C,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.C), images.C)
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

func (f *Formatter) setVulnerabilityData(results []flawfinderEntities.Result, index int) *vulnerability.Vulnerability {
	vuln := f.getDefaultVulnerabilitySeverity()
	vuln.Severity = results[index].GetSeverity()
	vuln.Details = results[index].GetDetails()
	vuln.Line = results[index].Line
	vuln.Column = results[index].Column
	vuln.Code = f.GetCodeWithMaxCharacters(results[index].Context, 0)
	vuln.File = results[index].GetFilename()
	vuln = vulnhash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.Flawfinder
	vulnerabilitySeverity.Language = languages.C
	return vulnerabilitySeverity
}
