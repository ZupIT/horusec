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

	"github.com/ZupIT/horusec/development-kit/pkg/engines/leaks/analysis"
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
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
	if f.ToolIsToIgnore(tools.HorusecLeaks) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.HorusecLeaks.ToString(), logger.DebugLevel)
		return
	}
	err := f.startHorusecLeaksAnalysis(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.HorusecLeaks, projectSubPath)
}

func (f *Formatter) startHorusecLeaksAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.HorusecLeaks)

	findings := f.execEngine(projectSubPath)

	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.HorusecLeaks)
	return f.setOutputInHorusecAnalysis(findings)
}

func (f *Formatter) execEngine(projectSubPath string) []engine.Finding {
	controller := analysis.NewAnalysis(&config.Config{ProjectPath: f.GetConfigProjectPath() + "/" + projectSubPath})
	return controller.StartAnalysisCustomRules(nil)
}

func (f *Formatter) setOutputInHorusecAnalysis(reportOutput []engine.Finding) error {
	for index := range reportOutput {
		vulnerability := f.setupVulnerabilitiesSeverities(reportOutput, index)
		vulnerability = f.setupCommitAuthorInVulnerability(vulnerability)

		// Set vulnerabilitySeverity.VulnHash value
		vulnerability = vulnhash.Bind(vulnerability)

		f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
			horusec.AnalysisVulnerabilities{
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
