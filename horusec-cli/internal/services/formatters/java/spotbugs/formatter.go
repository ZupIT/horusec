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

package spotbugs

import (
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/java/spotbugs/entities"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
)

const (
	highMaxSeverityValue   = 9
	mediumMinSeverityValue = 10
	mediumMaxSeverityValue = 14
)

const (
	confidenceHigh   = "1"
	confidenceMedium = "2"
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
	if f.ToolIsToIgnore(tools.SpotBugs) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.SpotBugs.ToString(), logger.DebugLevel)
		return
	}
	err := f.startSpotbugsAnalysis(projectSubPath)
	f.SetToolFinishedAnalysis()
	f.SetAnalysisError(err, tools.SpotBugs, projectSubPath)
}

func (f *Formatter) startSpotbugsAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.SpotBugs)

	output, err := f.ExecuteContainer(f.getImageTagCmd(projectSubPath))
	if err != nil {
		return err
	}

	if err := f.verifyOutputErrors(output); err != nil {
		return err
	}

	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.SpotBugs)
	return f.formatOutput(output)
}

func (f *Formatter) formatOutput(outputXML string) error {
	javaOutput := entities.SpotBugsOutput{}
	if outputXML == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty, logger.DebugLevel,
			map[string]interface{}{"tool": tools.SpotBugs.ToString()})
		f.setOutputInHorusecAnalysis(&javaOutput)
		return nil
	}
	javaOutput, err := f.convertOutputAndValidate(outputXML, &javaOutput)
	if err != nil {
		return err
	}
	f.setOutputInHorusecAnalysis(&javaOutput)
	return nil
}

func (f *Formatter) convertOutputAndValidate(
	outputXML string, javaOutput *entities.SpotBugsOutput) (entities.SpotBugsOutput, error) {
	if err := xml.Unmarshal([]byte(outputXML), javaOutput); err != nil {
		logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.SpotBugs, outputXML), err, logger.ErrorLevel)
		return *javaOutput, err
	}
	if err := f.validateErrors(javaOutput); err != nil {
		return *javaOutput, err
	}
	return *javaOutput, nil
}

func (f *Formatter) validateErrors(javaOutput *entities.SpotBugsOutput) error {
	numOfErrors, numOfMissingClasses, err := f.getNumErrorsNumMissingClasses(javaOutput)
	if err != nil {
		return err
	}
	if (len(javaOutput.SpotBugsIssue) == 0) && (numOfErrors > 0 || numOfMissingClasses > 0) {
		msg := strings.ReplaceAll(messages.MsgSpotBugsMissingClassesOrErrors, "{{0}}", strconv.Itoa(numOfMissingClasses))
		msg = strings.ReplaceAll(msg, "{{1}}", strconv.Itoa(numOfErrors))
		return errors.New(msg)
	}
	return nil
}

func (f *Formatter) getNumErrorsNumMissingClasses(javaOutput *entities.SpotBugsOutput) (int, int, error) {
	numOfErrors, err := strconv.Atoi(javaOutput.Errors.Errors)
	if err != nil {
		return 0, 0, err
	}
	numOfMissingClasses, err := strconv.Atoi(javaOutput.Errors.MissingClasses)
	if err != nil {
		return 0, 0, err
	}
	return numOfErrors, numOfMissingClasses, nil
}

func (f *Formatter) setOutputInHorusecAnalysis(javaOutput *entities.SpotBugsOutput) {
	for indexSpotBugsIssue := range javaOutput.SpotBugsIssue {
		for indexSourceLine := range javaOutput.SpotBugsIssue[indexSpotBugsIssue].SourceLine {
			vulnerability := f.setupVulnerabilitiesSeverities(javaOutput, indexSpotBugsIssue, indexSourceLine)
			if f.isJavaOutput(f.getVulnerabilitiesSeveritiesFile(javaOutput, indexSpotBugsIssue, indexSourceLine)) {
				vulnerability.Language = languages.Java
			} else {
				vulnerability.Language = languages.Kotlin
			}
			f.factoryAddVulnerabilityBySeverity(&vulnerability)
		}
	}
}

func (f *Formatter) setupVulnerabilitiesSeverities(
	javaOutput *entities.SpotBugsOutput, indexSpotBugsIssue, indexSourceLine int) (
	vulnerabilitySeverity horusec.Vulnerability) {
	vulnerabilitySeverity.Severity = f.parseSpotbugsRankToSeverity(javaOutput, indexSpotBugsIssue)
	vulnerabilitySeverity.Details = javaOutput.SpotBugsIssue[indexSpotBugsIssue].Type
	vulnerabilitySeverity.Code = f.getVulnerabilitiesSeveritiesCode(javaOutput, indexSpotBugsIssue, indexSourceLine)
	vulnerabilitySeverity.Line = f.getVulnerabilitiesSeveritiesLine(javaOutput, indexSpotBugsIssue, indexSourceLine)
	vulnerabilitySeverity.Column = ""
	vulnerabilitySeverity.Confidence = f.parseSpotbugsPriorityToConfidence(javaOutput, indexSpotBugsIssue)
	vulnerabilitySeverity.File = f.getVulnerabilitiesSeveritiesFile(javaOutput, indexSpotBugsIssue, indexSourceLine)
	vulnerabilitySeverity.SecurityTool = tools.SpotBugs
	// TODO: Check on tool to return full path of the file to get commit author
	return vulnerabilitySeverity
}

func (f *Formatter) parseSpotbugsPriorityToConfidence(javaOutput *entities.SpotBugsOutput,
	indexSpotBugsIssue int) string {
	switch javaOutput.SpotBugsIssue[indexSpotBugsIssue].Priority {
	case confidenceHigh:
		return "HIGH"
	case confidenceMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func (f *Formatter) parseSpotbugsRankToSeverity(
	javaOutput *entities.SpotBugsOutput, indexSpotBugsIssue int) severity.Severity {
	rank, _ := strconv.Atoi(javaOutput.SpotBugsIssue[indexSpotBugsIssue].Rank)
	switch {
	case rank <= highMaxSeverityValue:
		return severity.High
	case rank >= mediumMinSeverityValue && rank <= mediumMaxSeverityValue:
		return severity.Medium
	default:
		return severity.Low
	}
}

func (f *Formatter) getVulnerabilitiesSeveritiesLine(
	javaOutput *entities.SpotBugsOutput, indexSpotBugsIssue, indexSourceLine int) string {
	return javaOutput.SpotBugsIssue[indexSpotBugsIssue].SourceLine[indexSourceLine].Start
}

func (f *Formatter) getVulnerabilitiesSeveritiesFile(
	javaOutput *entities.SpotBugsOutput, indexSpotBugsIssue, indexSourceLine int) string {
	return javaOutput.SpotBugsIssue[indexSpotBugsIssue].SourceLine[indexSourceLine].SourcePath
}

func (f *Formatter) getVulnerabilitiesSeveritiesCode(
	javaOutput *entities.SpotBugsOutput, indexSpotBugsIssue, indexSourceLine int) string {
	startLine := javaOutput.SpotBugsIssue[indexSpotBugsIssue].SourceLine[indexSourceLine].Start
	endLine := javaOutput.SpotBugsIssue[indexSpotBugsIssue].SourceLine[indexSourceLine].End
	return fmt.Sprintf("Code beetween Line %s and Line %s.", startLine, endLine)
}

func (f *Formatter) factoryAddVulnerabilityBySeverity(vulnerability *horusec.Vulnerability) {
	f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
		horusec.AnalysisVulnerabilities{
			Vulnerability: *vulnerability,
		})
}

func (f *Formatter) isJavaOutput(fileName string) bool {
	if isKotlin, _ := regexp.MatchString("^.*.(kt|kts)$", fileName); isKotlin {
		return false
	}

	return true
}

func (f *Formatter) getImageTagCmd(projectSubPath string) *dockerEntities.AnalysisData {
	ad := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.SpotBugs),
		Language: languages.Java,
	}
	ad.SetFullImagePath(f.GetToolsConfig()[tools.SpotBugs].ImagePath, ImageName, ImageTag)
	return ad
}

func (f *Formatter) verifyOutputErrors(output string) (err error) {
	if strings.Contains(output, "ERROR_UNSUPPORTED_JAVA_PROJECT") {
		err = errors.New("error unsupported java project")
	}

	if strings.Contains(output, "ERROR_RUNNING_MAVEN_BUILD") {
		err = fmt.Errorf("error running maven build -> %s", output)
	}

	if strings.Contains(output, "ERROR_RUNNING_GRADLE_BUILD") {
		err = fmt.Errorf("error running gradle build -> %s", output)
	}

	return err
}
