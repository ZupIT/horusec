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

package safety

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/python"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	fileUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/file"
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
	err := f.startSafetyAnalysis(projectSubPath)
	f.LogAnalysisError(err, tools.Safety, projectSubPath)
	f.SetLanguageIsFinished()
}

func (f *Formatter) startSafetyAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Safety)

	output, err := f.ExecuteContainer(f.getAnalysisData(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.parseOutput(output)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Safety)
	return nil
}

func (f *Formatter) getAnalysisData(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image: ImageName,
		Tag:   ImageTag,
		CMD: f.AddWorkDirInCmd(ImageCmd,
			fileUtil.GetSubPathByExtension(f.GetConfigProjectPath(), projectSubPath, "requirements.txt"), tools.Safety),
		Language: languages.Python,
	}
}

func (f *Formatter) parseOutput(output string) {
	if output == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty, logger.DebugLevel,
			map[string]interface{}{"tool": tools.Safety.ToString()})
		return
	}
	if len(output) >= 19 && strings.EqualFold(output[:19], "ERROR_REQ_NOT_FOUND") {
		f.GetAnalysis().SetAnalysisError(errors.New(messages.MsgErrorNotFoundRequirementsTxt))
		output = ""
	}
	safetyOutput, err := f.parseOutputToSafetyOutput(output)
	if err != nil {
		return
	}
	f.setSafetyOutPutInHorusecAnalysis(safetyOutput.Issues)
}

func (f *Formatter) parseOutputToSafetyOutput(output string) (safetyOutput python.SafetyOutput, err error) {
	err = jsonUtils.ConvertStringToOutput(output, &safetyOutput)
	logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.Safety, output), err, logger.ErrorLevel)
	return safetyOutput, err
}

func (f *Formatter) setSafetyOutPutInHorusecAnalysis(issues []python.SafetyIssues) {
	for index := range issues {
		vulnerability := f.setupVulnerabilitiesSeveritiesSafety(issues, index)
		f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
			horusec.AnalysisVulnerabilities{
				Vulnerability: *vulnerability,
			})
	}
}

func (f *Formatter) setupVulnerabilitiesSeveritiesSafety(
	issues []python.SafetyIssues, index int) *horusec.Vulnerability {
	lineContent := fmt.Sprintf("%s=%s", issues[index].Dependency, issues[index].InstalledVersion)

	vulnerabilitySeverity := f.getDefaultVulnerabilitySeverityInSafety()
	vulnerabilitySeverity.Details = issues[index].Description
	vulnerabilitySeverity.Code = f.GetCodeWithMaxCharacters(issues[index].Dependency, 0)
	vulnerabilitySeverity.Line = f.getVulnerabilityLineByName(lineContent, vulnerabilitySeverity.File)

	// Set vulnerabilitySeverity.VulnHash value
	vulnerabilitySeverity = vulnhash.Bind(vulnerabilitySeverity)

	return f.setCommitAuthor(vulnerabilitySeverity)
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

func (f *Formatter) getVulnerabilityLineByName(line, file string) string {
	path := fmt.Sprintf("%s/%s", f.GetConfigProjectPath(), file)
	fileOpened, err := os.Open(path)
	if err != nil {
		return "-"
	}

	defer func() {
		logger.LogErrorWithLevel(messages.MsgErrorDeferFileClose, fileOpened.Close(), logger.ErrorLevel)
	}()
	scanner := bufio.NewScanner(fileOpened)
	return f.getLine(line, scanner)
}

func (f *Formatter) getLine(name string, scanner *bufio.Scanner) string {
	line := 1
	for scanner.Scan() {
		if strings.Contains(strings.ToLower(scanner.Text()), strings.ToLower(name)) {
			return strconv.Itoa(line)
		}

		line++
	}

	return "-"
}

func (f *Formatter) getDefaultVulnerabilitySeverityInSafety() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.Language = languages.Python
	vulnerabilitySeverity.Severity = severity.Audit
	vulnerabilitySeverity.SecurityTool = tools.Safety
	vulnerabilitySeverity.Confidence = "-"
	vulnerabilitySeverity.Column = "0"
	vulnerabilitySeverity.File = "requirements.txt"
	return vulnerabilitySeverity
}
