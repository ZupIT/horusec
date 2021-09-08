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

	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	enumsAnalysis "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	enumsVulnerability "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/config"
	languagedetect "github.com/ZupIT/horusec/internal/controllers/language_detect"
	"github.com/ZupIT/horusec/internal/controllers/printresults"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/docker"
	dockerClient "github.com/ZupIT/horusec/internal/services/docker/client"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/c/flawfinder"
	dotnetcli "github.com/ZupIT/horusec/internal/services/formatters/csharp/dotnet_cli"
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/horuseccsharp"
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/scs"
	"github.com/ZupIT/horusec/internal/services/formatters/dart/horusecdart"
	"github.com/ZupIT/horusec/internal/services/formatters/elixir/mixaudit"
	"github.com/ZupIT/horusec/internal/services/formatters/elixir/sobelow"
	dependencycheck "github.com/ZupIT/horusec/internal/services/formatters/generic/dependency_check"
	"github.com/ZupIT/horusec/internal/services/formatters/generic/semgrep"
	"github.com/ZupIT/horusec/internal/services/formatters/generic/trivy"
	"github.com/ZupIT/horusec/internal/services/formatters/go/gosec"
	"github.com/ZupIT/horusec/internal/services/formatters/go/nancy"
	"github.com/ZupIT/horusec/internal/services/formatters/hcl/checkov"
	"github.com/ZupIT/horusec/internal/services/formatters/hcl/tfsec"
	"github.com/ZupIT/horusec/internal/services/formatters/java/horusecjava"
	"github.com/ZupIT/horusec/internal/services/formatters/javascript/horusecnodejs"
	"github.com/ZupIT/horusec/internal/services/formatters/javascript/npmaudit"
	"github.com/ZupIT/horusec/internal/services/formatters/javascript/yarnaudit"
	"github.com/ZupIT/horusec/internal/services/formatters/kotlin/horuseckotlin"
	"github.com/ZupIT/horusec/internal/services/formatters/leaks/gitleaks"
	"github.com/ZupIT/horusec/internal/services/formatters/leaks/horusecleaks"
	"github.com/ZupIT/horusec/internal/services/formatters/nginx/horusecnginx"
	"github.com/ZupIT/horusec/internal/services/formatters/php/phpcs"
	"github.com/ZupIT/horusec/internal/services/formatters/python/bandit"
	"github.com/ZupIT/horusec/internal/services/formatters/python/safety"
	"github.com/ZupIT/horusec/internal/services/formatters/ruby/brakeman"
	"github.com/ZupIT/horusec/internal/services/formatters/ruby/bundler"
	"github.com/ZupIT/horusec/internal/services/formatters/shell/shellcheck"
	"github.com/ZupIT/horusec/internal/services/formatters/swift/horusecswift"
	"github.com/ZupIT/horusec/internal/services/formatters/yaml/horuseckubernetes"
	horusecAPI "github.com/ZupIT/horusec/internal/services/horusec_api"
	"github.com/ZupIT/horusec/internal/utils/file"
)

const LoadingDelay = 200 * time.Millisecond

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
	SendAnalysis(*analysis.Analysis)
	GetAnalysis(uuid.UUID) *analysis.Analysis
}

type Analyzer struct {
	docker          docker.Docker
	analysis        *analysis.Analysis
	config          *config.Config
	languageDetect  LanguageDetect
	printController PrintResults
	horusec         HorusecService
	formatter       formatters.IService
	loading         *spinner.Spinner
}

//nolint:funlen
func NewAnalyzer(cfg *config.Config) *Analyzer {
	entity := &analysis.Analysis{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		Status:    enumsAnalysis.Running,
	}
	dockerAPI := docker.New(dockerClient.NewDockerClient(), cfg, entity.ID)
	return &Analyzer{
		docker:          dockerAPI,
		analysis:        entity,
		config:          cfg,
		languageDetect:  languagedetect.NewLanguageDetect(cfg, entity.ID),
		printController: printresults.NewPrintResults(entity, cfg),
		horusec:         horusecAPI.NewHorusecAPIService(cfg),
		formatter:       formatters.NewFormatterService(entity, dockerAPI, cfg),
		loading:         newScanLoading(),
	}
}

func (a *Analyzer) Analyze() (totalVulns int, err error) {
	a.removeTrashByInterruptProcess()
	totalVulns, err = a.runAnalysis()
	a.removeHorusecFolder()
	return totalVulns, err
}

func (a *Analyzer) removeTrashByInterruptProcess() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			a.removeHorusecFolder()
			log.Fatal()
		}
	}()
}

func (a *Analyzer) removeHorusecFolder() {
	err := os.RemoveAll(a.config.GetProjectPath() + file.ReplacePathSeparator("/.horusec"))
	logger.LogErrorWithLevel(messages.MsgErrorRemoveAnalysisFolder, err)
	if !a.config.GetDisableDocker() {
		a.docker.DeleteContainersFromAPI()
	}
}

func (a *Analyzer) runAnalysis() (totalVulns int, err error) {
	langs, err := a.languageDetect.Detect(a.config.GetProjectPath())
	if err != nil {
		return 0, err
	}
	a.startDetectVulnerabilities(langs)
	return a.sendAnalysisAndStartPrintResults()
}

func (a *Analyzer) sendAnalysisAndStartPrintResults() (int, error) {
	a.formatAnalysisToSendToAPI()
	a.horusec.SendAnalysis(a.analysis)
	analysisSaved := a.horusec.GetAnalysis(a.analysis.ID)
	if analysisSaved != nil && analysisSaved.ID != uuid.Nil {
		a.analysis = analysisSaved
	}

	a.formatAnalysisToPrint()
	a.printController.SetAnalysis(a.analysis)
	return a.printController.Print()
}

func (a *Analyzer) formatAnalysisToPrint() {
	a.analysis = a.setFalsePositive()
	if !a.config.GetEnableInformationSeverity() {
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
	if !a.config.GetEnableInformationSeverity() {
		a.analysis = a.removeInfoVulnerabilities()
	}
}

// nolint:funlen,gocyclo
// NOTE: We ignore the funlen and gocyclo lint here because concurrency code is complicated
//
// startDetectVulnerabilities handle execution of all analysis in parallel
func (a *Analyzer) startDetectVulnerabilities(langs []languages.Language) {
	var wg sync.WaitGroup
	done := make(chan struct{})

	wd := a.config.GetWorkDir()
	funcs := a.mapDetectVulnerabilityByLanguage()

	a.loading.Start()

	go func() {
		defer close(done)
		for _, language := range langs {
			for _, subPath := range wd.GetArrayByLanguage(language) {
				projectSubPath := subPath
				a.logProjectSubPath(language, projectSubPath)

				if fn, exist := funcs[language]; exist {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if err := fn(&wg, projectSubPath); err != nil {
							a.setAnalysisError(err)
						}
					}()
				}
			}
		}
		wg.Wait()
	}()

	timeout := a.config.GetTimeoutInSecondsAnalysis()
	timer := time.After(time.Duration(timeout) * time.Second)
	retry := a.config.GetMonitorRetryInSeconds()
	tick := time.NewTicker(time.Duration(retry) * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-done:
			a.loading.Stop()
			return
		case <-timer:
			a.docker.DeleteContainersFromAPI()
			a.config.IsTimeout = true
			a.loading.Stop()
			return
		case <-tick.C:
			timeout -= retry
		}
	}
}

//nolint:funlen // all Languages is greater than 15
func (a *Analyzer) mapDetectVulnerabilityByLanguage() map[languages.Language]func(*sync.WaitGroup, string) error {
	return map[languages.Language]func(*sync.WaitGroup, string) error{
		languages.CSharp:     a.detectVulnerabilityCsharp,
		languages.Leaks:      a.detectVulnerabilityLeaks,
		languages.Go:         a.detectVulnerabilityGo,
		languages.Java:       a.detectVulnerabilityJava,
		languages.Kotlin:     a.detectVulnerabilityKotlin,
		languages.Javascript: a.detectVulnerabilityJavascript,
		languages.Python:     a.detectVulnerabilityPython,
		languages.Ruby:       a.detectVulnerabilityRuby,
		languages.HCL:        a.detectVulnerabilityHCL,
		languages.Generic:    a.detectVulnerabilityGeneric,
		languages.Yaml:       a.detectVulnerabilityYaml,
		languages.C:          a.detectVulnerabilityC,
		languages.PHP:        a.detectVulnerabilityPHP,
		languages.Dart:       a.detectVulnerabilityDart,
		languages.Elixir:     a.detectVulnerabilityElixir,
		languages.Shell:      a.detectVulnerabilityShell,
		languages.Nginx:      a.detectVulnerabilityNginx,
		languages.Swift:      a.detectVulneravilitySwift,
	}
}

func (a *Analyzer) detectVulneravilitySwift(_ *sync.WaitGroup, projectSubPath string) error {
	horusecswift.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityCsharp(wg *sync.WaitGroup, projectSubPath string) error {
	spawn(wg, horuseccsharp.NewFormatter(a.formatter), projectSubPath)

	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.CSharp)); err != nil {
		return err
	}

	scs.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	dotnetcli.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityLeaks(wg *sync.WaitGroup, projectSubPath string) error {
	spawn(wg, horusecleaks.NewFormatter(a.formatter), projectSubPath)

	if a.config.GetEnableGitHistoryAnalysis() {
		logger.LogWarnWithLevel(messages.MsgWarnGitHistoryEnable)

		if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Leaks)); err != nil {
			return err
		}
		gitleaks.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	}
	return nil
}

func (a *Analyzer) detectVulnerabilityGo(_ *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Go)); err != nil {
		return err
	}

	gosec.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	nancy.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityJava(_ *sync.WaitGroup, projectSubPath string) error {
	horusecjava.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityKotlin(_ *sync.WaitGroup, projectSubPath string) error {
	horuseckotlin.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityNginx(_ *sync.WaitGroup, projectSubPath string) error {
	horusecnginx.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityJavascript(wg *sync.WaitGroup, projectSubPath string) error {
	spawn(wg, horusecnodejs.NewFormatter(a.formatter), projectSubPath)

	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Javascript)); err != nil {
		return err
	}
	spawn(wg, yarnaudit.NewFormatter(a.formatter), projectSubPath)
	npmaudit.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityPython(wg *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Python)); err != nil {
		return err
	}
	spawn(wg, bandit.NewFormatter(a.formatter), projectSubPath)
	safety.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityRuby(wg *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Ruby)); err != nil {
		return err
	}
	spawn(wg, brakeman.NewFormatter(a.formatter), projectSubPath)
	bundler.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityHCL(_ *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.HCL)); err != nil {
		return err
	}
	tfsec.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	checkov.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityYaml(_ *sync.WaitGroup, projectSubPath string) error {
	horuseckubernetes.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityC(_ *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.C)); err != nil {
		return err
	}
	flawfinder.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityPHP(_ *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.PHP)); err != nil {
		return err
	}
	phpcs.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityGeneric(_ *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Generic)); err != nil {
		return err
	}

	trivy.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	semgrep.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	dependencycheck.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityDart(_ *sync.WaitGroup, projectSubPath string) error {
	horusecdart.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityElixir(wg *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Elixir)); err != nil {
		return err
	}
	spawn(wg, mixaudit.NewFormatter(a.formatter), projectSubPath)
	sobelow.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) detectVulnerabilityShell(_ *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Shell)); err != nil {
		return err
	}
	shellcheck.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Analyzer) logProjectSubPath(language languages.Language, subPath string) {
	if subPath != "" {
		msg := fmt.Sprintf("Running %s in subpath: %s", language.ToString(), subPath)
		logger.LogDebugWithLevel(msg)
	}
}

func (a *Analyzer) checkIfNoExistHashAndLog(list []string) {
	for _, hash := range list {
		existing := false
		for keyAv := range a.analysis.AnalysisVulnerabilities {
			if hash == a.analysis.AnalysisVulnerabilities[keyAv].Vulnerability.VulnHash {
				existing = true
				break
			}
		}
		if !existing {
			logger.LogWarnWithLevel(messages.MsgWarnHashNotExistOnAnalysis + hash)
		}
	}
}

func (a *Analyzer) setFalsePositive() *analysis.Analysis {
	a.analysis = a.SetFalsePositivesAndRiskAcceptInVulnerabilities(
		a.config.GetFalsePositiveHashes(), a.config.GetRiskAcceptHashes())

	a.checkIfNoExistHashAndLog(a.config.GetFalsePositiveHashes())
	a.checkIfNoExistHashAndLog(a.config.GetRiskAcceptHashes())
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
func (a *Analyzer) getCustomOrDefaultImage(language languages.Language) string {
	if customImage := a.config.GetCustomImages()[language.GetCustomImagesKeyByLanguage()]; customImage != "" {
		return customImage
	}
	return fmt.Sprintf("%s/%s", images.DefaultRegistry, images.MapValues()[language])
}

func (a *Analyzer) SetFalsePositivesAndRiskAcceptInVulnerabilities(
	listFalsePositive, listRiskAccept []string) *analysis.Analysis {
	for key := range a.analysis.AnalysisVulnerabilities {
		a.setVulnerabilityType(key, listFalsePositive, enumsVulnerability.FalsePositive)
		a.setVulnerabilityType(key, listRiskAccept, enumsVulnerability.RiskAccepted)
	}
	return a.analysis
}

func (a *Analyzer) setVulnerabilityType(keyAnalysisVulnerabilities int,
	listToCheck []string, vulnerabilityType enumsVulnerability.Type) {
	currentHash := a.analysis.AnalysisVulnerabilities[keyAnalysisVulnerabilities].Vulnerability.VulnHash
	for _, flagVulnerabilityHash := range listToCheck {
		if flagVulnerabilityHash != "" && strings.TrimSpace(currentHash) == strings.TrimSpace(flagVulnerabilityHash) {
			a.analysis.AnalysisVulnerabilities[keyAnalysisVulnerabilities].Vulnerability.Type = vulnerabilityType
		}
	}
}

func (a *Analyzer) setAnalysisFinishedData() *analysis.Analysis {
	a.analysis.FinishedAt = time.Now()

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
		a.getVulnerabilitiesByType(enumsVulnerability.RiskAccepted)...)
	analysisVulnerabilities = append(analysisVulnerabilities,
		a.getVulnerabilitiesByType(enumsVulnerability.FalsePositive)...)
	analysisVulnerabilities = append(analysisVulnerabilities,
		a.getVulnerabilitiesByType(enumsVulnerability.Corrected)...)
	a.analysis.AnalysisVulnerabilities = analysisVulnerabilities
	return a.analysis
}

func (a *Analyzer) getVulnerabilitiesByType(
	vulnType enumsVulnerability.Type) (response []analysis.AnalysisVulnerabilities) {
	for index := range a.analysis.AnalysisVulnerabilities {
		if a.analysis.AnalysisVulnerabilities[index].Vulnerability.Type == vulnType {
			response = append(response, a.analysis.AnalysisVulnerabilities[index])
		}
	}
	return response
}

func (a *Analyzer) getVulnerabilitiesBySeverity(
	search severities.Severity) (response []analysis.AnalysisVulnerabilities) {
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

func (a *Analyzer) removeVulnerabilitiesBySeverity() *analysis.Analysis {
	var vulnerabilities []analysis.AnalysisVulnerabilities
	severitiesToIgnore := a.config.GetSeveritiesToIgnore()

outer:
	for index := range a.analysis.AnalysisVulnerabilities {
		vuln := a.analysis.AnalysisVulnerabilities[index]
		for _, severity := range severitiesToIgnore {
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
		for _, acceptedType := range a.config.GetShowVulnerabilitiesTypes() {
			if strings.EqualFold(vulnType.ToString(), acceptedType) {
				vulnerabilities = append(vulnerabilities, a.analysis.AnalysisVulnerabilities[index])
				break
			}
		}
	}

	a.analysis.AnalysisVulnerabilities = vulnerabilities

	return a.analysis
}

func spawn(wg *sync.WaitGroup, f formatters.IFormatter, src string) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		f.StartAnalysis(src)
	}()
}

func newScanLoading() *spinner.Spinner {
	loading := spinner.New(spinner.CharSets[11], LoadingDelay)
	loading.Suffix = messages.MsgInfoAnalysisLoading

	return loading
}
