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

	"github.com/ZupIT/horusec/development-kit/pkg/enums/cli"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/sonarqube"

	horusecEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

var (
	ErrOutputJSON = errors.New("{HORUSEC_CLI} error creating and/or writing to the specified file")
)

type PrintResults struct {
	analysis         *horusecEntities.Analysis
	configs          *config.Config
	totalVulns       int
	sonarqubeService sonarqube.Interface
}

type Interface interface {
	StartPrintResults() (totalVulns int, err error)
}

func NewPrintResults(analysis *horusecEntities.Analysis, configs *config.Config) Interface {
	return &PrintResults{
		analysis:         analysis,
		configs:          configs,
		sonarqubeService: sonarqube.NewSonarQube(analysis),
	}
}

func (pr *PrintResults) StartPrintResults() (totalVulns int, err error) {
	if err := pr.factoryPrintByType(); err != nil {
		return 0, err
	}

	pr.checkIfExistVulnerabilityOrNoSec()
	pr.verifyRepositoryAuthorizationToken()
	pr.printResponseAnalysis()
	pr.checkIfExistsErrorsInAnalysis()

	if pr.configs.IsTimeout {
		logger.LogWarnWithLevel(messages.MsgErrorTimeoutOccurs, logger.ErrorLevel)
	}

	return pr.totalVulns, nil
}

func (pr *PrintResults) factoryPrintByType() error {
	switch {
	case pr.configs.PrintOutputType == string(cli.JSON):
		return pr.runPrintResultsJSON()
	case pr.configs.PrintOutputType == string(cli.SonarQube):
		return pr.runPrintResultsSonarQube()
	default:
		return pr.runPrintResultsText()
	}
}

// nolint
func (pr *PrintResults) runPrintResultsText() error {
	pr.logSeparator()

	fmt.Println(fmt.Sprintf("HORUSEC ENDED THE ANALYSIS COM STATUS OF \"%s\" AND WITH THE FOLLOWING RESULTS:", pr.analysis.Status))

	pr.logSeparator()

	fmt.Println(fmt.Sprintf("Analysis StartedAt: %s", pr.analysis.CreatedAt.Format("2006-01-02 15:04:05")))
	fmt.Println(fmt.Sprintf("Analysis FinishedAt: %s", pr.analysis.FinishedAt.Format("2006-01-02 15:04:05")))

	pr.logSeparator()

	pr.printTextOutputVulnerability()
	return nil
}

func (pr *PrintResults) runPrintResultsJSON() error {
	bytesToWrite, err := json.MarshalIndent(pr.analysis, "", "  ")
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorGenerateJSONFile, err, logger.ErrorLevel)
		return err
	}
	return pr.parseFilePathToAbsAndCreateOutputJSON(bytesToWrite)
}

func (pr *PrintResults) runPrintResultsSonarQube() error {
	return pr.saveSonarQubeFormatResults()
}

func (pr *PrintResults) checkIfExistVulnerabilityOrNoSec() {
	for key := range pr.analysis.Vulnerabilities {
		severityType := pr.analysis.Vulnerabilities[key].Severity.ToString()
		if severityType != "" {
			if !pr.isIgnoredVulnerability(severityType) {
				pr.totalVulns++
			}
		}
	}
}

func (pr *PrintResults) isIgnoredVulnerability(vulnerabilityType string) (ignore bool) {
	listTypesToIgnore := strings.Split(pr.configs.TypesOfVulnerabilitiesToIgnore, ",")
	ignore = false

	for _, typeToIgnore := range listTypesToIgnore {
		if strings.EqualFold(vulnerabilityType, strings.TrimSpace(typeToIgnore)) ||
			vulnerabilityType == string(severity.NoSec) || vulnerabilityType == string(severity.Info) {
			ignore = true
			return ignore
		}
	}

	return ignore
}

func (pr *PrintResults) saveSonarQubeFormatResults() error {
	logger.LogInfoWithLevel(messages.MsgInfoStartGenerateSonarQubeFile, logger.InfoLevel)
	report := pr.sonarqubeService.ConvertVulnerabilityDataToSonarQube()
	bytesToWrite, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorGenerateJSONFile, err, logger.ErrorLevel)
		return err
	}
	return pr.parseFilePathToAbsAndCreateOutputJSON(bytesToWrite)
}

func (pr *PrintResults) returnDefaultErrOutputJSON(err error) error {
	logger.LogErrorWithLevel(messages.MsgErrorGenerateJSONFile, err, logger.ErrorLevel)
	return ErrOutputJSON
}

func (pr *PrintResults) parseFilePathToAbsAndCreateOutputJSON(bytesToWrite []byte) error {
	completePath, err := filepath.Abs(pr.configs.JSONOutputFilePath)
	if err != nil {
		return pr.returnDefaultErrOutputJSON(err)
	}
	if _, err := os.Create(completePath); err != nil {
		return pr.returnDefaultErrOutputJSON(err)
	}
	logger.LogInfoWithLevel(messages.MsgInfoStartWriteFile+completePath, logger.InfoLevel)
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
	for index := range pr.analysis.Vulnerabilities {
		vulnerability := pr.analysis.Vulnerabilities[index]
		pr.printTextOutputVulnerabilityData(&vulnerability)
	}

	pr.printTotalVulnerabilities()

	pr.logSeparator()
}

func (pr *PrintResults) printTotalVulnerabilities() {
	totalVulnerabilities := pr.analysis.GetTotalVulnerabilities()
	totalVulnerabilitiesBySeverity := pr.analysis.GetTotalVulnerabilitiesBySeverity()
	for severityName, count := range totalVulnerabilitiesBySeverity {
		if count > 0 {
			fmt.Println(fmt.Sprintf("Total of Vulnerabilities %s is: %v",
				severityName.ToString(), count))
		}
	}

	if totalVulnerabilities > 0 {
		fmt.Println(fmt.Sprintf("A total of %v vulnerabilities were found in this analysis",
			totalVulnerabilities))
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
	fmt.Println(fmt.Sprintf("File: %s", vulnerability.File))
	fmt.Println(fmt.Sprintf("Code: %s", vulnerability.Code))
	fmt.Println(fmt.Sprintf("Details: %s", vulnerability.Details))

	pr.printCommitAuthor(vulnerability)

	fmt.Println(fmt.Sprintf("ReferenceHash: %s", vulnerability.VulnHash))

	fmt.Print("\n")

	pr.logSeparator()
}

// nolint
func (pr *PrintResults) printCommitAuthor(vulnerability *horusecEntities.Vulnerability) {
	if !pr.configs.IsCommitAuthorEnable() {
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
		logger.LogWarnWithLevel(messages.MsgWarnAuthorizationNotFound, logger.WarnLevel)
		fmt.Print("\n")
	}
}

func (pr *PrintResults) checkIfExistsErrorsInAnalysis() {
	if pr.analysis.HasErrors() {
		logger.LogErrorWithLevel(messages.MsgErrorFoundErrorsInAnalysis, errors.New(pr.analysis.Errors), logger.ErrorLevel)
		fmt.Print("\n")
	}
}

func (pr *PrintResults) printResponseAnalysis() {
	if pr.totalVulns > 0 {
		logger.LogWarnWithLevel(fmt.Sprintf(messages.MsgAnalysisFoundVulns, pr.totalVulns), logger.WarnLevel)
		fmt.Print("\n")
		return
	}

	logger.LogWarnWithLevel(messages.MsgAnalysisFinishedWithoutVulns, logger.WarnLevel)
	fmt.Print("\n")
}

func (pr *PrintResults) logSeparator() {
	fmt.Println(fmt.Sprintf("\n==================================================================================\n"))
}
