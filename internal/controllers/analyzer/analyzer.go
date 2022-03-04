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

package analyzer

import (
	"fmt"
	"strings"
	"time"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	enumsAnalysis "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	enumsVulnerability "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec/config"
	languagedetect "github.com/ZupIT/horusec/internal/controllers/language_detect"
	"github.com/ZupIT/horusec/internal/controllers/printresults"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/docker/client"
	horusec_api "github.com/ZupIT/horusec/internal/services/horusec_api"
)

// LanguageDetect is the interface that detect all languages in some directory.
type LanguageDetect interface {
	Detect(directory string) ([]languages.Language, error)
}

// PrintResults is the interface tha print the results to stdout
//
// Print print the results to stdout and return the total vulnerabilities that was printed.
type PrintResults interface {
	Print() (int, error)
	SetAnalysis(analysis *analysis.Analysis)
}

// HorusecService is the interface that interacts with Horusec API
type HorusecService interface {
	SendAnalysis(*analysis.Analysis) error
	GetAnalysis(uuid.UUID) (*analysis.Analysis, error)
}

// Analyzer is responsible to orchestrate the pipeline of an analysis.
//
// Basically, an analysis has the following steps:
// 	1 - Detect all languages on project path.
// 	2 - Execute all tools to all languages founded.
//	3 - Send analysis to Horusuec Manager if access token is set.
//	4 - Print analysis results.
type Analyzer struct {
	analysis        *analysis.Analysis
	config          *config.Config
	languageDetect  LanguageDetect
	printController PrintResults
	horusec         HorusecService
	runner          *runner
}

// New create a new analyzer to a given config.
func New(cfg *config.Config) *Analyzer {
	analysiss := &analysis.Analysis{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		Status:    enumsAnalysis.Running,
	}
	dockerAPI := docker.New(client.NewDockerClient(), cfg, analysiss.ID)
	return &Analyzer{
		analysis:        analysiss,
		config:          cfg,
		languageDetect:  languagedetect.NewLanguageDetect(cfg, analysiss.ID),
		printController: printresults.NewPrintResults(analysiss, cfg),
		horusec:         horusec_api.NewHorusecAPIService(cfg),
		runner:          newRunner(cfg, analysiss, dockerAPI),
	}
}

// Analyze start an analysis and return the total of vulnerabilities founded
// and an error if exists.
//
// nolint: funlen
func (a *Analyzer) Analyze() (int, error) {
	langs, err := a.languageDetect.Detect(a.config.ProjectPath)
	if err != nil {
		return 0, err
	}

	if a.config.EnableGitHistoryAnalysis {
		logger.LogWarnWithLevel(messages.MsgWarnGitHistoryEnable)
		fmt.Println()
	}

	for _, err := range a.runner.run(langs) {
		a.setAnalysisError(err)
	}

	if err = a.sendAnalysis(); err != nil {
		logger.LogStringAsError(fmt.Sprintf("[HORUSEC] %s", err.Error()))
	}

	return a.startPrintResults()
}

func (a *Analyzer) startPrintResults() (int, error) {
	a.formatAnalysisToPrint()
	a.printController.SetAnalysis(a.analysis)
	return a.printController.Print()
}

func (a *Analyzer) sendAnalysis() error {
	a.formatAnalysisToSendToAPI()
	if err := a.horusec.SendAnalysis(a.analysis); err != nil {
		return err
	}
	analysisSaved, err := a.horusec.GetAnalysis(a.analysis.ID)
	if err != nil {
		return err
	}
	if analysisSaved != nil && analysisSaved.ID != uuid.Nil {
		a.analysis = analysisSaved
	}
	return err
}

func (a *Analyzer) formatAnalysisToPrint() {
	a.setUpdateHashWarnings()

	a.analysis = a.setFalsePositive()
	if !a.config.EnableInformationSeverity {
		a.analysis = a.removeInfoVulnerabilities()
	}
	a.analysis = a.removeVulnerabilitiesByTypes()
	a.analysis = a.removeVulnerabilitiesBySeverity()
}

func (a *Analyzer) formatAnalysisToSendToAPI() {
	a.analysis = a.setAnalysisFinishedData()
	a.analysis = a.setupIDInAnalysisContents()
	a.analysis = a.sortVulnerabilitiesByCriticality()
	a.analysis = a.setDefaultVulnerabilityType()
	a.analysis = a.setDefaultConfidence()
	a.analysis = a.sortVulnerabilitiesByType()
	if !a.config.EnableInformationSeverity {
		a.analysis = a.removeInfoVulnerabilities()
	}
}

// logWarnIfHashDontExistsInConfig logs a warning if the one of the config hashes don't exist in the analysis.
// nolint
func (a *Analyzer) logWarnIfHashDontExistsInConfig(configHashes []string) {
	for _, configHash := range configHashes {
		exists := false

		for vulnIndex := range a.analysis.AnalysisVulnerabilities {
			// See vulnerability.Vulnerability.DeprecatedHashes docs for more info.
			hashes := make([]string, len(a.analysis.AnalysisVulnerabilities[vulnIndex].Vulnerability.DeprecatedHashes)+1)
			hashes = append(hashes, a.analysis.AnalysisVulnerabilities[vulnIndex].Vulnerability.DeprecatedHashes...)
			hashes = append(hashes, a.analysis.AnalysisVulnerabilities[vulnIndex].Vulnerability.VulnHash)
			if a.contains(hashes, configHash) {
				exists = true
				break
			}
		}

		if !exists {
			logger.LogWarnWithLevel(messages.MsgWarnHashNotExistOnAnalysis + configHash)
		}
	}
}

func (a *Analyzer) contains(hashes []string, hash string) bool {
	for _, v := range hashes {
		if hash == v {
			return true
		}
	}

	return false
}

func (a *Analyzer) setFalsePositive() *analysis.Analysis {
	a.analysis = a.SetFalsePositivesAndRiskAcceptInVulnerabilities(
		a.config.FalsePositiveHashes, a.config.RiskAcceptHashes)

	a.logWarnIfHashDontExistsInConfig(a.getAllConfigHashes())

	return a.analysis
}

func (a *Analyzer) setAnalysisError(err error) {
	if err != nil {
		toAppend := ""
		if len(a.analysis.Errors) > 0 {
			a.analysis.Errors += "; " + err.Error()
			return
		}
		a.analysis.Errors += toAppend + err.Error()
	}
}

// SetFalsePositivesAndRiskAcceptInVulnerabilities set analysis vulnerabilities to false
// positive or risk accept if the hash exists on falsePositive and riskAccept params.
//
// nolint:lll
func (a *Analyzer) SetFalsePositivesAndRiskAcceptInVulnerabilities(falsePositive, riskAccept []string) *analysis.Analysis {
	for idx := range a.analysis.AnalysisVulnerabilities {
		a.setVulnerabilityType(
			&a.analysis.AnalysisVulnerabilities[idx].Vulnerability, falsePositive, enumsVulnerability.FalsePositive,
		)
		a.setVulnerabilityType(
			&a.analysis.AnalysisVulnerabilities[idx].Vulnerability, riskAccept, enumsVulnerability.RiskAccepted,
		)
	}
	return a.analysis
}

//nolint:gocyclo // complexity will be reduced after removing the deprecated hashes
func (a *Analyzer) setVulnerabilityType(
	vuln *vulnerability.Vulnerability, hashes []string, vulnType enumsVulnerability.Type,
) {
	for _, hash := range hashes {
		hash = strings.TrimSpace(hash)

		// See vulnerability.Vulnerability.DeprecatedHashes docs for more info.
		for _, deprecatedHash := range vuln.DeprecatedHashes {
			if hash != "" && (strings.TrimSpace(vuln.VulnHash) == hash || strings.TrimSpace(deprecatedHash) == hash) {
				vuln.Type = vulnType
				return
			}
		}
	}
}

func (a *Analyzer) setAnalysisFinishedData() *analysis.Analysis {
	a.analysis.FinishedAt = time.Now()

	a.removeWarningsFromErrors()
	if a.analysis.HasErrors() {
		a.analysis.Status = enumsAnalysis.Error
		return a.analysis
	}

	a.analysis.Status = enumsAnalysis.Success
	return a.analysis
}

func (a *Analyzer) setupIDInAnalysisContents() *analysis.Analysis {
	for key := range a.analysis.AnalysisVulnerabilities {
		a.analysis.AnalysisVulnerabilities[key].SetCreatedAt()
		a.analysis.AnalysisVulnerabilities[key].SetAnalysisID(a.analysis.ID)
		a.analysis.AnalysisVulnerabilities[key].Vulnerability.VulnerabilityID = uuid.New()
	}
	return a.analysis
}

func (a *Analyzer) sortVulnerabilitiesByCriticality() *analysis.Analysis {
	analysisVulnerabilities := a.getVulnerabilitiesBySeverity(severities.Critical)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.High)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Medium)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Low)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Unknown)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Info)...)
	a.analysis.AnalysisVulnerabilities = analysisVulnerabilities
	return a.analysis
}

func (a *Analyzer) sortVulnerabilitiesByType() *analysis.Analysis {
	analysisVulnerabilities := a.getVulnerabilitiesByType(enumsVulnerability.Vulnerability)
	analysisVulnerabilities = append(analysisVulnerabilities,
		a.getVulnerabilitiesByType(enumsVulnerability.RiskAccepted)...,
	)
	analysisVulnerabilities = append(analysisVulnerabilities,
		a.getVulnerabilitiesByType(enumsVulnerability.FalsePositive)...,
	)
	analysisVulnerabilities = append(analysisVulnerabilities,
		a.getVulnerabilitiesByType(enumsVulnerability.Corrected)...,
	)
	a.analysis.AnalysisVulnerabilities = analysisVulnerabilities
	return a.analysis
}

func (a *Analyzer) getVulnerabilitiesByType(
	vulnType enumsVulnerability.Type,
) (response []analysis.AnalysisVulnerabilities) {
	for index := range a.analysis.AnalysisVulnerabilities {
		if a.analysis.AnalysisVulnerabilities[index].Vulnerability.Type == vulnType {
			response = append(response, a.analysis.AnalysisVulnerabilities[index])
		}
	}
	return response
}

func (a *Analyzer) getVulnerabilitiesBySeverity(
	search severities.Severity,
) (response []analysis.AnalysisVulnerabilities) {
	for index := range a.analysis.AnalysisVulnerabilities {
		if a.analysis.AnalysisVulnerabilities[index].Vulnerability.Severity == search {
			response = append(response, a.analysis.AnalysisVulnerabilities[index])
		}
	}
	return response
}

func (a *Analyzer) setDefaultVulnerabilityType() *analysis.Analysis {
	for key := range a.analysis.AnalysisVulnerabilities {
		a.analysis.AnalysisVulnerabilities[key].Vulnerability.Type = enumsVulnerability.Vulnerability
	}
	return a.analysis
}

func (a *Analyzer) setDefaultConfidence() *analysis.Analysis {
	for key := range a.analysis.AnalysisVulnerabilities {
		valid := false
		for _, conf := range confidence.Values() {
			if conf == a.analysis.AnalysisVulnerabilities[key].Vulnerability.Confidence {
				valid = true
				break
			}
		}
		if !valid {
			a.analysis.AnalysisVulnerabilities[key].Vulnerability.Confidence = confidence.Low
		}
	}
	return a.analysis
}

func (a *Analyzer) removeInfoVulnerabilities() *analysis.Analysis {
	var vulnerabilities []analysis.AnalysisVulnerabilities

	for index := range a.analysis.AnalysisVulnerabilities {
		if a.analysis.AnalysisVulnerabilities[index].Vulnerability.Severity != severities.Info {
			vulnerabilities = append(vulnerabilities, a.analysis.AnalysisVulnerabilities[index])
		}
	}

	a.analysis.AnalysisVulnerabilities = vulnerabilities

	return a.analysis
}

// nolint: funlen,gocyclo
func (a *Analyzer) removeVulnerabilitiesBySeverity() *analysis.Analysis {
	var vulnerabilities []analysis.AnalysisVulnerabilities
	severitiesToIgnore := a.config.SeveritiesToIgnore

outer:
	for index := range a.analysis.AnalysisVulnerabilities {
		vuln := a.analysis.AnalysisVulnerabilities[index]
		for _, severity := range severitiesToIgnore {
			// Force to print INFO vulnerabilities when information severity is enabled.
			if severity == severities.Info.ToString() && a.config.EnableInformationSeverity {
				continue
			}

			if strings.EqualFold(string(vuln.Vulnerability.Severity), severity) {
				continue outer
			}
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	a.analysis.AnalysisVulnerabilities = vulnerabilities
	return a.analysis
}

func (a *Analyzer) removeVulnerabilitiesByTypes() *analysis.Analysis {
	var vulnerabilities []analysis.AnalysisVulnerabilities

	for index := range a.analysis.AnalysisVulnerabilities {
		vulnType := a.analysis.AnalysisVulnerabilities[index].Vulnerability.Type
		for _, acceptedType := range a.config.ShowVulnerabilitiesTypes {
			if strings.EqualFold(vulnType.ToString(), acceptedType) {
				vulnerabilities = append(vulnerabilities, a.analysis.AnalysisVulnerabilities[index])
				break
			}
		}
	}

	a.analysis.AnalysisVulnerabilities = vulnerabilities

	return a.analysis
}

// setUpdateHashWarnings checks for hashes generated in older formats but that are still valid. If one of
// these hashes are found, a warning will be showed informing the user to update the outdated hash.
// TODO: Remove setUpdateHashWarnings before release v2.10.0
// nolint
func (a *Analyzer) setUpdateHashWarnings() {
	isPrintDepreciationMsg := true
	configHashes := a.getAllConfigHashes()

	vulnerabilities := a.analysis.AnalysisVulnerabilities
	for vulnIndex := range vulnerabilities {
		for _, deprecatedHash := range vulnerabilities[vulnIndex].Vulnerability.DeprecatedHashes {
			for _, configHash := range configHashes {
				if deprecatedHash == configHash {
					if isPrintDepreciationMsg {
						a.analysis.AddWarning(messages.MsgWarnAnalysisContainsOutdatedHash)
						isPrintDepreciationMsg = false
					}

					a.analysis.AddWarning(fmt.Sprintf(messages.MsgWarnUpdateOutdatedHash,
						configHash, vulnerabilities[vulnIndex].Vulnerability.VulnHash))
				}
			}
		}
	}
}

func (a *Analyzer) getAllConfigHashes() []string {
	size := len(a.config.FalsePositiveHashes) + len(a.config.RiskAcceptHashes)

	configHashes := make([]string, size)
	configHashes = append(configHashes, a.config.FalsePositiveHashes...)
	configHashes = append(configHashes, a.config.RiskAcceptHashes...)

	return configHashes
}

// removeWarningsFromErrors workaround to separate warnings from errors until the formatters are refactored
func (a *Analyzer) removeWarningsFromErrors() {
	var errors string

	for _, err := range strings.SplitAfter(a.analysis.Errors, ";") {
		if a.isWarning(err) {
			a.analysis.AddWarning(err)
		} else {
			errors += err
		}
	}

	a.analysis.Errors = errors
}

// isWarning workaround to check if the message it's form a warning until the formatters are refactored
func (a *Analyzer) isWarning(err string) bool {
	return strings.Contains(err, messages.MsgErrorPacketJSONNotFound) ||
		strings.Contains(err, messages.MsgErrorYarnLockNotFound) ||
		strings.Contains(err, messages.MsgErrorGemLockNotFound) ||
		strings.Contains(err, messages.MsgErrorNotFoundRequirementsTxt)
}
