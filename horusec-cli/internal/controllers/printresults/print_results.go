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

package printresults

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	horusecEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/enums/outputtype"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/sonarqube"
)

var (
	ErrOutputJSON = errors.New("{HORUSEC_CLI} error creating and/or writing to the specified file")
)

type PrintResults struct {
	analysis         *horusecEntities.Analysis
	configs          config.IConfig
	totalVulns       int
	sonarqubeService sonarqube.Interface
}

type Interface interface {
	StartPrintResults() (totalVulns int, err error)
	SetAnalysis(analysis *horusecEntities.Analysis)
}

func NewPrintResults(analysis *horusecEntities.Analysis, configs config.IConfig) Interface {
	return &PrintResults{
		analysis:         analysis,
		configs:          configs,
		sonarqubeService: sonarqube.NewSonarQube(analysis),
	}
}

func (pr *PrintResults) SetAnalysis(analysis *horusecEntities.Analysis) {
	pr.analysis = analysis
}

func (pr *PrintResults) StartPrintResults() (totalVulns int, err error) {
	if err := pr.factoryPrintByType(); err != nil {
		return 0, err
	}

	pr.checkIfExistVulnerabilityOrNoSec()
	pr.verifyRepositoryAuthorizationToken()
	pr.printResponseAnalysis()
	pr.checkIfExistsErrorsInAnalysis()
	if pr.configs.GetIsTimeout() {
		logger.LogWarnWithLevel(messages.MsgErrorTimeoutOccurs)
	}

	return pr.totalVulns, nil
}

func (pr *PrintResults) factoryPrintByType() error {
	switch {
	case pr.configs.GetPrintOutputType() == string(outputtype.JSON):
		return pr.runPrintResultsJSON()
	case pr.configs.GetPrintOutputType() == string(outputtype.SonarQube):
		return pr.runPrintResultsSonarQube()
	default:
		return pr.runPrintResultsText()
	}
}

// nolint
func (pr *PrintResults) runPrintResultsText() error {
	pr.logSeparator(true)

	fmt.Println(fmt.Sprintf("HORUSEC ENDED THE ANALYSIS WITH STATUS OF \"%s\" AND WITH THE FOLLOWING RESULTS:", pr.analysis.Status))

	pr.logSeparator(true)

	fmt.Println(fmt.Sprintf("Analysis StartedAt: %s", pr.analysis.CreatedAt.Format("2006-01-02 15:04:05")))
	fmt.Println(fmt.Sprintf("Analysis FinishedAt: %s", pr.analysis.FinishedAt.Format("2006-01-02 15:04:05")))

	pr.logSeparator(true)

	pr.printTextOutputVulnerability()
	return nil
}

func (pr *PrintResults) runPrintResultsJSON() error {
	bytesToWrite, err := json.MarshalIndent(pr.analysis, "", "  ")
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorGenerateJSONFile, err)
		return err
	}
	return pr.parseFilePathToAbsAndCreateOutputJSON(bytesToWrite)
}

func (pr *PrintResults) runPrintResultsSonarQube() error {
	return pr.saveSonarQubeFormatResults()
}

func (pr *PrintResults) checkIfExistVulnerabilityOrNoSec() {
	for key := range pr.analysis.AnalysisVulnerabilities {
		vuln := pr.analysis.AnalysisVulnerabilities[key].Vulnerability
		pr.validateVulnerabilityToCheckTotalErrors(&vuln)
	}
	if logger.CurrentLevel >= logger.DebugLevel {
		pr.logSeparator(len(pr.analysis.AnalysisVulnerabilities) > 0)
	}
}

func (pr *PrintResults) validateVulnerabilityToCheckTotalErrors(vuln *horusecEntities.Vulnerability) {
	if vuln.Severity.ToString() != "" && !pr.isTypeVulnToSkip(vuln) {
		if !pr.isIgnoredVulnerability(vuln.Severity.ToString()) {
			logger.LogDebugWithLevel(messages.MsgDebugVulnHashToFix + vuln.VulnHash)
			if logger.CurrentLevel >= logger.DebugLevel {
				fmt.Println("")
			}
			pr.totalVulns++
		}
	}
}

func (pr *PrintResults) isTypeVulnToSkip(vuln *horusecEntities.Vulnerability) bool {
	return vuln.Type == horusec.FalsePositive || vuln.Type == horusec.RiskAccepted || vuln.Type == horusec.Corrected
}

func (pr *PrintResults) isIgnoredVulnerability(vulnerabilityType string) (ignore bool) {
	ignore = false

	for _, typeToIgnore := range pr.configs.GetSeveritiesToIgnore() {
		if strings.EqualFold(vulnerabilityType, strings.TrimSpace(typeToIgnore)) ||
			vulnerabilityType == string(severity.NoSec) || vulnerabilityType == string(severity.Info) {
			ignore = true
			return ignore
		}
	}

	return ignore
}

func (pr *PrintResults) saveSonarQubeFormatResults() error {
	logger.LogInfoWithLevel(messages.MsgInfoStartGenerateSonarQubeFile)
	report := pr.sonarqubeService.ConvertVulnerabilityDataToSonarQube()
	bytesToWrite, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorGenerateJSONFile, err)
		return err
	}
	return pr.parseFilePathToAbsAndCreateOutputJSON(bytesToWrite)
}

func (pr *PrintResults) returnDefaultErrOutputJSON(err error) error {
	logger.LogErrorWithLevel(messages.MsgErrorGenerateJSONFile, err)
	return ErrOutputJSON
}

func (pr *PrintResults) parseFilePathToAbsAndCreateOutputJSON(bytesToWrite []byte) error {
	completePath, err := filepath.Abs(pr.configs.GetJSONOutputFilePath())
	if err != nil {
		return pr.returnDefaultErrOutputJSON(err)
	}
	if _, err := os.Create(completePath); err != nil {
		return pr.returnDefaultErrOutputJSON(err)
	}
	logger.LogInfoWithLevel(messages.MsgInfoStartWriteFile + completePath)
	return pr.openJSONFileAndWriteBytes(bytesToWrite, completePath)
}

func (pr *PrintResults) openJSONFileAndWriteBytes(bytesToWrite []byte, completePath string) error {
	outputFile, err := os.OpenFile(completePath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return pr.returnDefaultErrOutputJSON(err)
	}
	if err = outputFile.Truncate(0); err != nil {
		return pr.returnDefaultErrOutputJSON(err)
	}
	bytesWritten, err := outputFile.Write(bytesToWrite)
	if err != nil || bytesWritten != len(bytesToWrite) {
		return pr.returnDefaultErrOutputJSON(err)
	}
	return outputFile.Close()
}

func (pr *PrintResults) printTextOutputVulnerability() {
	for index := range pr.analysis.AnalysisVulnerabilities {
		vulnerability := pr.analysis.AnalysisVulnerabilities[index].Vulnerability
		pr.printTextOutputVulnerabilityData(&vulnerability)
	}

	pr.printTotalVulnerabilities()

	pr.logSeparator(len(pr.analysis.AnalysisVulnerabilities) > 0)
}

func (pr *PrintResults) printTotalVulnerabilities() {
	totalVulnerabilities := pr.analysis.GetTotalVulnerabilities()
	if totalVulnerabilities > 0 {
		fmt.Println(fmt.Sprintf("In this analysis, a total of %v possible vulnerabilities "+
			"were found and we classified them into:", totalVulnerabilities))
		fmt.Println("")
	}
	totalVulnerabilitiesBySeverity := pr.analysis.GetTotalVulnerabilitiesBySeverity()
	for vulnType, countBySeverity := range totalVulnerabilitiesBySeverity {
		for severityName, count := range countBySeverity {
			if count > 0 {
				fmt.Println(fmt.Sprintf("Total of %s %s is: %v", vulnType.ToString(), severityName.ToString(), count))
			}
		}
	}
}

// nolint
func (pr *PrintResults) printTextOutputVulnerabilityData(vulnerability *horusecEntities.Vulnerability) {
	fmt.Println(fmt.Sprintf("Language: %s", vulnerability.Language))
	fmt.Println(fmt.Sprintf("Severity: %s", vulnerability.Severity))
	fmt.Println(fmt.Sprintf("Line: %s", vulnerability.Line))
	fmt.Println(fmt.Sprintf("Column: %s", vulnerability.Column))
	fmt.Println(fmt.Sprintf("SecurityTool: %s", vulnerability.SecurityTool))
	fmt.Println(fmt.Sprintf("Confidence: %s", vulnerability.Confidence))
	fmt.Println(fmt.Sprintf("File: %s", pr.getProjectPath(vulnerability.File)))
	fmt.Println(fmt.Sprintf("Code: %s", vulnerability.Code))
	fmt.Println(fmt.Sprintf("Details: %s", vulnerability.Details))
	fmt.Println(fmt.Sprintf("Type: %s", vulnerability.Type))

	pr.printCommitAuthor(vulnerability)

	fmt.Println(fmt.Sprintf("ReferenceHash: %s", vulnerability.VulnHash))

	fmt.Print("\n")

	pr.logSeparator(true)
}

// nolint
func (pr *PrintResults) printCommitAuthor(vulnerability *horusecEntities.Vulnerability) {
	if !pr.configs.GetEnableCommitAuthor() {
		return
	}
	fmt.Println(fmt.Sprintf("Commit Author: %s", vulnerability.CommitAuthor))
	fmt.Println(fmt.Sprintf("Commit Date: %s", vulnerability.CommitDate))
	fmt.Println(fmt.Sprintf("Commit Email: %s", vulnerability.CommitEmail))
	fmt.Println(fmt.Sprintf("Commit CommitHash: %s", vulnerability.CommitHash))
	fmt.Println(fmt.Sprintf("Commit Message: %s", vulnerability.CommitMessage))

}

func (pr *PrintResults) verifyRepositoryAuthorizationToken() {
	if pr.configs.IsEmptyRepositoryAuthorization() {
		fmt.Print("\n")
		logger.LogWarnWithLevel(messages.MsgWarnAuthorizationNotFound)
		fmt.Print("\n")
	}
}

func (pr *PrintResults) checkIfExistsErrorsInAnalysis() {
	if !pr.configs.GetEnableInformationSeverity() {
		logger.LogWarnWithLevel(messages.MsgWarnInfoVulnerabilitiesDisabled)
	}
	if pr.analysis.HasErrors() {
		pr.logSeparator(true)
		logger.LogWarnWithLevel(messages.MsgErrorFoundErrorsInAnalysis)
		fmt.Print("\n")

		for _, errorMessage := range strings.SplitAfter(pr.analysis.Errors, ";") {
			pr.printErrors(errorMessage)
		}

		fmt.Print("\n")
	}
}

func (pr *PrintResults) printErrors(errorMessage string) {
	if strings.Contains(errorMessage, messages.MsgErrorPacketJSONNotFound) ||
		strings.Contains(errorMessage, messages.MsgErrorYarnLockNotFound) ||
		strings.Contains(errorMessage, messages.MsgErrorGemLockNotFound) {
		logger.LogWarnWithLevel(strings.ReplaceAll(errorMessage, ";", ""))
		return
	}

	logger.LogStringAsError(strings.ReplaceAll(errorMessage, ";", ""))
}

func (pr *PrintResults) printResponseAnalysis() {
	if pr.totalVulns > 0 {
		logger.LogWarnWithLevel(fmt.Sprintf(messages.MsgAnalysisFoundVulns, pr.totalVulns))
		fmt.Print("\n")
		return
	}

	logger.LogWarnWithLevel(messages.MsgAnalysisFinishedWithoutVulns)
	fmt.Print("\n")
}

func (pr *PrintResults) logSeparator(isToShow bool) {
	if isToShow {
		fmt.Println(fmt.Sprintf("\n==================================================================================\n"))
	}
}

func (pr *PrintResults) getProjectPath(path string) string {
	if strings.Contains(path, pr.configs.GetProjectPath()) {
		return path
	}

	if pr.configs.GetContainerBindProjectPath() != "" {
		return fmt.Sprintf("%s/%s", pr.configs.GetContainerBindProjectPath(), path)
	}

	return fmt.Sprintf("%s/%s", pr.configs.GetProjectPath(), path)
}
