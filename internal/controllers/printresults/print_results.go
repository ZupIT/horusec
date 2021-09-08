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

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	enumsVulnerability "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/config"
	sq "github.com/ZupIT/horusec/internal/entities/sonarqube"
	"github.com/ZupIT/horusec/internal/enums/outputtype"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/sonarqube"
	"github.com/ZupIT/horusec/internal/utils/file"
)

var (
	ErrOutputJSON = errors.New("{HORUSEC_CLI} error creating and/or writing to the specified file")
)

type SonarQubeConverter interface {
	ConvertVulnerabilityToSonarQube() sq.Report
}

type analysisOutputJSON struct {
	Version string `json:"version"`
	analysis.Analysis
}

type PrintResults struct {
	analysis         *analysis.Analysis
	configs          *config.Config
	totalVulns       int
	sonarqubeService SonarQubeConverter
	textOutput       string
}

func NewPrintResults(entity *analysis.Analysis, configs *config.Config) *PrintResults {
	return &PrintResults{
		analysis:         entity,
		configs:          configs,
		sonarqubeService: sonarqube.NewSonarQube(entity),
	}
}

func (pr *PrintResults) SetAnalysis(entity *analysis.Analysis) {
	pr.analysis = entity
}

func (pr *PrintResults) Print() (totalVulns int, err error) {
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
	case pr.configs.GetPrintOutputType() == outputtype.JSON:
		return pr.runPrintResultsJSON()
	case pr.configs.GetPrintOutputType() == outputtype.SonarQube:
		return pr.runPrintResultsSonarQube()
	default:
		return pr.runPrintResultsText()
	}
}

func (pr *PrintResults) runPrintResultsText() error {
	fmt.Print("\n")
	pr.logSeparator(true)

	pr.printLNF("HORUSEC ENDED THE ANALYSIS WITH STATUS OF \"%s\" AND WITH THE FOLLOWING RESULTS:", pr.analysis.Status)

	pr.logSeparator(true)

	pr.printLNF("Analysis StartedAt: %s", pr.analysis.CreatedAt.Format("2006-01-02 15:04:05"))
	pr.printLNF("Analysis FinishedAt: %s", pr.analysis.FinishedAt.Format("2006-01-02 15:04:05"))

	pr.logSeparator(true)

	pr.printTextOutputVulnerability()

	return pr.createTxtOutputFile()
}

func (pr *PrintResults) runPrintResultsJSON() error {
	a := analysisOutputJSON{
		Analysis: *pr.analysis,
		Version:  pr.configs.GetVersion(),
	}

	bytesToWrite, err := json.MarshalIndent(a, "", "  ")
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
	pr.logSeparator(len(pr.analysis.AnalysisVulnerabilities) > 0)
}

func (pr *PrintResults) validateVulnerabilityToCheckTotalErrors(vuln *vulnerability.Vulnerability) {
	if vuln.Severity.ToString() != "" && !pr.isTypeVulnToSkip(vuln) {
		if !pr.isIgnoredVulnerability(vuln.Severity.ToString()) {
			logger.LogDebugWithLevel(messages.MsgDebugVulnHashToFix + vuln.VulnHash)
			pr.totalVulns++
		}
	}
}

func (pr *PrintResults) isTypeVulnToSkip(vuln *vulnerability.Vulnerability) bool {
	return vuln.Type == enumsVulnerability.FalsePositive ||
		vuln.Type == enumsVulnerability.RiskAccepted ||
		vuln.Type == enumsVulnerability.Corrected
}

func (pr *PrintResults) isIgnoredVulnerability(vulnerabilityType string) (ignore bool) {
	ignore = false

	for _, typeToIgnore := range pr.configs.GetSeveritiesToIgnore() {
		if strings.EqualFold(vulnerabilityType, strings.TrimSpace(typeToIgnore)) ||
			vulnerabilityType == string(severities.Info) {
			ignore = true
			return ignore
		}
	}

	return ignore
}

func (pr *PrintResults) saveSonarQubeFormatResults() error {
	logger.LogInfoWithLevel(messages.MsgInfoStartGenerateSonarQubeFile)
	report := pr.sonarqubeService.ConvertVulnerabilityToSonarQube()
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

//nolint:gomnd // magic number
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
		vuln := pr.analysis.AnalysisVulnerabilities[index].Vulnerability
		pr.printTextOutputVulnerabilityData(&vuln)
	}

	pr.printTotalVulnerabilities()
}

func (pr *PrintResults) printTotalVulnerabilities() {
	totalVulnerabilities := pr.analysis.GetTotalVulnerabilities()
	if totalVulnerabilities > 0 {
		pr.printLNF("In this analysis, a total of %v possible vulnerabilities "+
			"were found and we classified them into:", totalVulnerabilities)
	}
	totalVulnerabilitiesBySeverity := pr.GetTotalVulnsBySeverity()
	for vulnType, countBySeverity := range totalVulnerabilitiesBySeverity {
		for severityName, count := range countBySeverity {
			if count > 0 {
				pr.printLNF("Total of %s %s is: %v", vulnType.ToString(), severityName.ToString(), count)
			}
		}
	}
}

func (pr *PrintResults) GetTotalVulnsBySeverity() (total map[enumsVulnerability.Type]map[severities.Severity]int) {
	total = pr.getDefaultTotalVulnBySeverity()
	for index := range pr.analysis.AnalysisVulnerabilities {
		vuln := pr.analysis.AnalysisVulnerabilities[index].Vulnerability
		total[vuln.Type][vuln.Severity]++
	}
	return total
}

func (pr *PrintResults) getDefaultTotalVulnBySeverity() map[enumsVulnerability.Type]map[severities.Severity]int {
	return map[enumsVulnerability.Type]map[severities.Severity]int{
		enumsVulnerability.Vulnerability: pr.getDefaultCountBySeverity(),
		enumsVulnerability.RiskAccepted:  pr.getDefaultCountBySeverity(),
		enumsVulnerability.FalsePositive: pr.getDefaultCountBySeverity(),
		enumsVulnerability.Corrected:     pr.getDefaultCountBySeverity(),
	}
}

func (pr *PrintResults) getDefaultCountBySeverity() map[severities.Severity]int {
	return map[severities.Severity]int{
		severities.Critical: 0,
		severities.High:     0,
		severities.Medium:   0,
		severities.Low:      0,
		severities.Unknown:  0,
		severities.Info:     0,
	}
}

// nolint
func (pr *PrintResults) printTextOutputVulnerabilityData(vulnerability *vulnerability.Vulnerability) {
	pr.printLNF("Language: %s", vulnerability.Language)
	pr.printLNF("Severity: %s", vulnerability.Severity)
	pr.printLNF("Line: %s", vulnerability.Line)
	pr.printLNF("Column: %s", vulnerability.Column)
	pr.printLNF("SecurityTool: %s", vulnerability.SecurityTool)
	pr.printLNF("Confidence: %s", vulnerability.Confidence)
	pr.printLNF("File: %s", pr.getProjectPath(vulnerability.File))
	pr.printLNF("Code: %s", vulnerability.Code)
	pr.printLNF("Details: %s", vulnerability.Details)
	pr.printLNF("Type: %s", vulnerability.Type)

	pr.printCommitAuthor(vulnerability)

	pr.printLNF("ReferenceHash: %s", vulnerability.VulnHash)

	pr.logSeparator(true)
}

// nolint
func (pr *PrintResults) printCommitAuthor(vulnerability *vulnerability.Vulnerability) {
	if !pr.configs.GetEnableCommitAuthor() {
		return
	}
	pr.printLNF("Commit Author: %s", vulnerability.CommitAuthor)
	pr.printLNF("Commit Date: %s", vulnerability.CommitDate)
	pr.printLNF("Commit Email: %s", vulnerability.CommitEmail)
	pr.printLNF("Commit CommitHash: %s", vulnerability.CommitHash)
	pr.printLNF("Commit Message: %s", vulnerability.CommitMessage)

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
		strings.Contains(errorMessage, messages.MsgErrorGemLockNotFound) ||
		strings.Contains(errorMessage, messages.MsgErrorNotFoundRequirementsTxt) {
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
		pr.printLNF("\n==================================================================================\n")
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

func (pr *PrintResults) printLNF(text string, args ...interface{}) {
	if pr.configs.GetPrintOutputType() == outputtype.Text {
		pr.textOutput += fmt.Sprintln(fmt.Sprintf(text, args...))
	}

	fmt.Println(fmt.Sprintf(text, args...))
}

func (pr *PrintResults) createTxtOutputFile() error {
	if pr.configs.GetPrintOutputType() != outputtype.Text || pr.configs.GetJSONOutputFilePath() == "" {
		return nil
	}

	return file.CreateAndWriteFile(pr.textOutput, pr.configs.GetJSONOutputFilePath())
}
