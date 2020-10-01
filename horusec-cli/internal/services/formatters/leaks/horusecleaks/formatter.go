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

package horusecleaks

import (
	"strconv"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	utilsHorusec "github.com/ZupIT/horusec/development-kit/pkg/utils/horusec"
	jsonUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/json"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
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
	err := f.startHorusecLeaksAnalysis(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.HorusecLeaks, projectSubPath)
}

func (f *Formatter) startHorusecLeaksAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.HorusecLeaks)

	output, err := f.ExecuteContainer(f.getImageTagCmd(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.HorusecLeaks)
	return f.formatOutput(output)
}

func (f *Formatter) getImageTagCmd(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath),
		Language: languages.Leaks,
	}
}

func (f *Formatter) formatOutput(output string) error {
	var reportOutput []engine.Finding
	if output == "" || output == "null" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty, logger.DebugLevel,
			map[string]interface{}{"tool": tools.HorusecLeaks.ToString()})

		return f.setOutputInHorusecAnalysis(reportOutput)
	}
	leaksOutput, err := f.convertOutputAndValidate(output, &reportOutput)
	if err != nil {
		return err
	}
	return f.setOutputInHorusecAnalysis(leaksOutput)
}

func (f *Formatter) convertOutputAndValidate(
	output string, reportOutput *[]engine.Finding) ([]engine.Finding, error) {
	if err := jsonUtils.ConvertStringToOutput(output, reportOutput); err != nil {
		logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.HorusecLeaks, output), err, logger.ErrorLevel)
		return *reportOutput, err
	}
	return *reportOutput, nil
}

func (f *Formatter) setOutputInHorusecAnalysis(reportOutput []engine.Finding) error {
	for index := range reportOutput {
		vulnerability := f.setupVulnerabilitiesSeverities(reportOutput, index)
		vulnerability = f.setupCommitAuthorInVulnerability(vulnerability)

		// Set vulnerabilitySeverity.VulnHash value
		vulnerability = vulnhash.Bind(vulnerability)

		f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities, horusec.AnalysisVulnerabilities{
			Vulnerability: *vulnerability,
		})
	}
	return nil
}

func (f *Formatter) setupVulnerabilitiesSeverities(reportOutput []engine.Finding,
	index int) (vulnerabilitySeverity *horusec.Vulnerability) {
	line := strconv.Itoa(reportOutput[index].SourceLocation.Line)
	column := strconv.Itoa(reportOutput[index].SourceLocation.Column)
	return &horusec.Vulnerability{
		Line:         line,
		Column:       column,
		Confidence:   reportOutput[index].Confidence,
		File:         f.RemoveSrcFolderFromPath(reportOutput[index].SourceLocation.Filename),
		Code:         f.GetCodeWithMaxCharacters(reportOutput[index].CodeSample, reportOutput[index].SourceLocation.Column),
		Details:      reportOutput[index].Name + "\n" + reportOutput[index].Description,
		SecurityTool: tools.HorusecLeaks,
		Language:     languages.Leaks,
		Severity: utilsHorusec.GetSeverityOrNoSec(severity.ParseStringToSeverity(reportOutput[index].Severity),
			reportOutput[index].CodeSample),
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
