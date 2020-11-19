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

package horuseccsharp

import (
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	"strconv"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	jsonUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/json"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
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
	if f.ToolIsToIgnore(tools.HorusecCsharp) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.HorusecCsharp.ToString(), logger.DebugLevel)
		return
	}

	err := f.startHorusecCsharpAnalysis(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.HorusecCsharp, projectSubPath)
}

func (f *Formatter) startHorusecCsharpAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.HorusecCsharp)

	output, err := f.ExecuteContainer(f.getImageTagCmd(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.HorusecCsharp)
	return f.formatOutput(output)
}

func (f *Formatter) getImageTagCmd(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.HorusecCsharp),
		Language: languages.CSharp,
	}
}

func (f *Formatter) formatOutput(output string) error {
	var reportOutput []engine.Finding

	if output == "" || output == "null" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty, logger.DebugLevel,
			map[string]interface{}{"tool": tools.HorusecCsharp.ToString()})

		return f.setOutputInHorusecAnalysis(reportOutput)
	}

	outputParsed, err := f.convertOutputAndValidate(output, &reportOutput)
	if err != nil {
		return err
	}

	return f.setOutputInHorusecAnalysis(outputParsed)
}

func (f *Formatter) convertOutputAndValidate(output string, reportOutput *[]engine.Finding) ([]engine.Finding, error) {
	if err := jsonUtils.ConvertStringToOutput(output, reportOutput); err != nil {
		logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.HorusecCsharp, output), err, logger.ErrorLevel)
		return *reportOutput, err
	}

	return *reportOutput, nil
}

func (f *Formatter) setOutputInHorusecAnalysis(reportOutput []engine.Finding) error {
	for index := range reportOutput {
		vulnerability := f.setupVulnerabilitiesSeverities(reportOutput, index)
		vulnerability = f.setupCommitAuthorInVulnerability(vulnerability)
		vulnerability = vulnhash.Bind(vulnerability)

		f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
			horusec.AnalysisVulnerabilities{
				Vulnerability: *vulnerability,
			})
	}
	return nil
}

func (f *Formatter) setupVulnerabilitiesSeverities(
	reportOutput []engine.Finding, index int) (
	vulnerabilitySeverity *horusec.Vulnerability) {
	line := strconv.Itoa(reportOutput[index].SourceLocation.Line)
	return &horusec.Vulnerability{
		Line:         line,
		Column:       strconv.Itoa(reportOutput[index].SourceLocation.Column),
		Confidence:   reportOutput[index].Confidence,
		File:         f.RemoveSrcFolderFromPath(reportOutput[index].SourceLocation.Filename),
		Code:         f.GetCodeWithMaxCharacters(reportOutput[index].CodeSample, reportOutput[index].SourceLocation.Column),
		Details:      reportOutput[index].Name + "\n" + reportOutput[index].Description,
		SecurityTool: tools.HorusecCsharp,
		Language:     languages.CSharp,
		Severity:     severity.ParseStringToSeverity(reportOutput[index].Severity),
	}
}
func (f *Formatter) setupCommitAuthorInVulnerability(vulnerability *horusec.Vulnerability) *horusec.Vulnerability {
	commitAuthor := f.GetCommitAuthor(vulnerability.Line, vulnerability.File)
	vulnerability.CommitAuthor = commitAuthor.Author
	vulnerability.CommitEmail = commitAuthor.Email
	vulnerability.CommitHash = commitAuthor.CommitHash
	vulnerability.CommitMessage = commitAuthor.Message
	vulnerability.CommitDate = commitAuthor.Date
	return vulnerability
}
