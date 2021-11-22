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
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	vulnerabilityenum "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
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

// PrintResults is reponsable to print results of an analysis
// to a given io.Writer.
type PrintResults struct {
	analysis         *analysis.Analysis
	config           *config.Config
	totalVulns       int
	sonarqubeService SonarQubeConverter
	textOutput       string
	writer           io.Writer
}

// NewPrintResults create a new PrintResults using os.Stdout as writer.
func NewPrintResults(entity *analysis.Analysis, cfg *config.Config) *PrintResults {
	return &PrintResults{
		analysis:         entity,
		config:           cfg,
		sonarqubeService: sonarqube.NewSonarQube(entity),
		writer:           os.Stdout,
		totalVulns:       0,
		textOutput:       "",
	}
}

func (pr *PrintResults) SetAnalysis(entity *analysis.Analysis) {
	pr.analysis = entity
}

func (pr *PrintResults) Print() (totalVulns int, err error) {
	if err := pr.printByOutputType(); err != nil {
		return 0, err
	}

	pr.checkIfExistVulnerabilityOrNoSec()
	pr.verifyRepositoryAuthorizationToken()
	pr.printResponseAnalysis()
	pr.checkIfExistsErrorsInAnalysis()
	if pr.config.IsTimeout {
		logger.LogWarnWithLevel(messages.MsgWarnTimeoutOccurs)
	}

	return pr.totalVulns, nil
}

func (pr *PrintResults) printByOutputType() error {
	switch {
	case pr.config.PrintOutputType == outputtype.JSON:
		return pr.printResultsJSON()
	case pr.config.PrintOutputType == outputtype.SonarQube:
		return pr.printResultsSonarQube()
	default:
		return pr.printResultsText()
	}
}

func (pr *PrintResults) printResultsText() error {
	fmt.Fprint(pr.writer, "\n")
	pr.logSeparator(true)

	pr.printlnf(`HORUSEC ENDED THE ANALYSIS WITH STATUS OF %q AND WITH THE FOLLOWING RESULTS:`, pr.analysis.Status)

	pr.logSeparator(true)

	pr.printlnf("Analysis StartedAt: %s", pr.analysis.CreatedAt.Format("2006-01-02 15:04:05"))
	pr.printlnf("Analysis FinishedAt: %s", pr.analysis.FinishedAt.Format("2006-01-02 15:04:05"))

	pr.logSeparator(true)

	pr.printTextOutputVulnerability()

	return pr.createTxtOutputFile()
}

func (pr *PrintResults) printResultsJSON() error {
	a := analysisOutputJSON{
		Analysis: *pr.analysis,
		Version:  pr.config.Version,
	}

	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorGenerateJSONFile, err)
		return err
	}

	return pr.createOutputJSON(b)
}

func (pr *PrintResults) printResultsSonarQube() error {
	logger.LogInfoWithLevel(messages.MsgInfoStartGenerateSonarQubeFile)

	report := pr.sonarqubeService.ConvertVulnerabilityToSonarQube()

	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorGenerateJSONFile, err)
		return err
	}

	return pr.createOutputJSON(b)
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
	return vuln.Type == vulnerabilityenum.FalsePositive ||
		vuln.Type == vulnerabilityenum.RiskAccepted ||
		vuln.Type == vulnerabilityenum.Corrected
}

func (pr *PrintResults) isIgnoredVulnerability(vulnerabilityType string) bool {
	for _, typeToIgnore := range pr.config.SeveritiesToIgnore {
		if strings.EqualFold(vulnerabilityType, strings.TrimSpace(typeToIgnore)) ||
			vulnerabilityType == string(severities.Info) {
			return true
		}
	}

	return false
}

func (pr *PrintResults) returnDefaultErrOutputJSON(err error) error {
	logger.LogErrorWithLevel(messages.MsgErrorGenerateJSONFile, err)
	return ErrOutputJSON
}

//nolint:funlen
func (pr *PrintResults) createOutputJSON(content []byte) error {
	path, err := filepath.Abs(pr.config.JSONOutputFilePath)
	if err != nil {
		return pr.returnDefaultErrOutputJSON(err)
	}

	f, err := os.Create(path)
	if err != nil {
		return pr.returnDefaultErrOutputJSON(err)
	}

	logger.LogInfoWithLevel(messages.MsgInfoStartWriteFile + path)

	if err := pr.truncateAndWriteFile(content, f); err != nil {
		return err
	}

	return f.Close()
}

func (pr *PrintResults) truncateAndWriteFile(content []byte, f *os.File) error {
	if err := f.Truncate(0); err != nil {
		return pr.returnDefaultErrOutputJSON(err)
	}

	bytesWritten, err := f.Write(content)
	if err != nil || bytesWritten != len(content) {
		return pr.returnDefaultErrOutputJSON(err)
	}

	return nil
}

func (pr *PrintResults) printTextOutputVulnerability() {
	for index := range pr.analysis.AnalysisVulnerabilities {
		vuln := pr.analysis.AnalysisVulnerabilities[index].Vulnerability
		pr.printTextOutputVulnerabilityData(&vuln)
	}

	pr.printTotalVulnerabilities()
}

//nolint:funlen
func (pr *PrintResults) printTotalVulnerabilities() {
	totalVulnerabilities := pr.analysis.GetTotalVulnerabilities()
	if totalVulnerabilities > 0 {
		pr.printlnf(
			"In this analysis, a total of %v possible vulnerabilities were found and we classified them into:",
			totalVulnerabilities,
		)
	}

	totalVulnerabilitiesBySeverity := pr.getTotalVulnsBySeverity()
	for vulnType, countBySeverity := range totalVulnerabilitiesBySeverity {
		for severityName, count := range countBySeverity {
			if count > 0 {
				pr.printlnf("Total of %s %s is: %v", vulnType.ToString(), severityName.ToString(), count)
			}
		}
	}
}

func (pr *PrintResults) getTotalVulnsBySeverity() map[vulnerabilityenum.Type]map[severities.Severity]int {
	total := pr.getDefaultTotalVulnBySeverity()

	for index := range pr.analysis.AnalysisVulnerabilities {
		vuln := pr.analysis.AnalysisVulnerabilities[index].Vulnerability
		total[vuln.Type][vuln.Severity]++
	}

	return total
}

func (pr *PrintResults) getDefaultTotalVulnBySeverity() map[vulnerabilityenum.Type]map[severities.Severity]int {
	count := pr.getDefaultCountBySeverity()
	return map[vulnerabilityenum.Type]map[severities.Severity]int{
		vulnerabilityenum.Vulnerability: count,
		vulnerabilityenum.RiskAccepted:  count,
		vulnerabilityenum.FalsePositive: count,
		vulnerabilityenum.Corrected:     count,
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
	pr.printlnf("Language: %s", vulnerability.Language)
	pr.printlnf("Severity: %s", vulnerability.Severity)
	pr.printlnf("Line: %s", vulnerability.Line)
	pr.printlnf("Column: %s", vulnerability.Column)
	pr.printlnf("SecurityTool: %s", vulnerability.SecurityTool)
	pr.printlnf("Confidence: %s", vulnerability.Confidence)
	pr.printlnf("File: %s", pr.getFilePath(vulnerability.File))
	pr.printlnf("Code: %s", vulnerability.Code)
	if vulnerability.RuleID != "" {
		pr.printlnf("RuleID: %s", vulnerability.RuleID)
	}
	pr.printlnf("Details: %s", vulnerability.Details)
	pr.printlnf("Type: %s", vulnerability.Type)

	pr.printCommitAuthor(vulnerability)

	pr.printlnf("ReferenceHash: %s", vulnerability.VulnHash)

	pr.logSeparator(true)
}

// nolint
func (pr *PrintResults) printCommitAuthor(vulnerability *vulnerability.Vulnerability) {
	if !pr.config.EnableCommitAuthor {
		return
	}
	pr.printlnf("Commit Author: %s", vulnerability.CommitAuthor)
	pr.printlnf("Commit Date: %s", vulnerability.CommitDate)
	pr.printlnf("Commit Email: %s", vulnerability.CommitEmail)
	pr.printlnf("Commit CommitHash: %s", vulnerability.CommitHash)
	pr.printlnf("Commit Message: %s", vulnerability.CommitMessage)

}

func (pr *PrintResults) verifyRepositoryAuthorizationToken() {
	if pr.config.IsEmptyRepositoryAuthorization() {
		fmt.Fprint(pr.writer, "\n")
		logger.LogWarnWithLevel(messages.MsgWarnAuthorizationNotFound)
		fmt.Fprint(pr.writer, "\n")
	}
}

func (pr *PrintResults) checkIfExistsErrorsInAnalysis() {
	if !pr.config.EnableInformationSeverity {
		logger.LogWarnWithLevel(messages.MsgWarnInfoVulnerabilitiesDisabled)
	}
	if pr.analysis.HasErrors() {
		pr.logSeparator(true)
		logger.LogWarnWithLevel(messages.MsgWarnFoundErrorsInAnalysis)
		fmt.Fprint(pr.writer, "\n")

		for _, errorMessage := range strings.SplitAfter(pr.analysis.Errors, ";") {
			pr.printErrors(errorMessage)
		}

		fmt.Fprint(pr.writer, "\n")
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
		logger.LogWarnWithLevel(fmt.Sprintf(messages.MsgWarnAnalysisFoundVulns, pr.totalVulns))
		fmt.Fprint(pr.writer, "\n")
		return
	}

	logger.LogWarnWithLevel(messages.MsgWarnAnalysisFinishedWithoutVulns)
	fmt.Fprint(pr.writer, "\n")
}

func (pr *PrintResults) logSeparator(isToShow bool) {
	if isToShow {
		pr.printlnf("\n==================================================================================\n")
	}
}

func (pr *PrintResults) getFilePath(path string) string {
	if strings.Contains(path, pr.config.ProjectPath) {
		return path
	}

	if pr.config.ContainerBindProjectPath != "" {
		return filepath.Join(pr.config.ContainerBindProjectPath, path)
	}

	return filepath.Join(pr.config.ProjectPath, path)
}

func (pr *PrintResults) printlnf(text string, args ...interface{}) {
	msg := fmt.Sprintf(text, args...)

	if pr.config.PrintOutputType == outputtype.Text {
		pr.textOutput += fmt.Sprintln(msg)
	}

	fmt.Fprintln(pr.writer, msg)
}

func (pr *PrintResults) createTxtOutputFile() error {
	if pr.config.PrintOutputType != outputtype.Text || pr.config.JSONOutputFilePath == "" {
		return nil
	}

	return file.CreateAndWriteFile(pr.textOutput, pr.config.JSONOutputFilePath)
}
