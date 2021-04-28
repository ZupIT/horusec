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

package analyser

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	enumsAnalysis "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	enumsVulnerability "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec/internal/entities/monitor"
	"github.com/ZupIT/horusec/internal/utils/file"

	"github.com/google/uuid"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	cliConfig "github.com/ZupIT/horusec/config"
	languageDetect "github.com/ZupIT/horusec/internal/controllers/language_detect"
	"github.com/ZupIT/horusec/internal/controllers/printresults"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/docker"
	dockerClient "github.com/ZupIT/horusec/internal/services/docker/client"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/c/flawfinder"
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/horuseccsharp"
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/scs"
	horusecDart "github.com/ZupIT/horusec/internal/services/formatters/dart/horusecdart"
	"github.com/ZupIT/horusec/internal/services/formatters/elixir/mixaudit"
	"github.com/ZupIT/horusec/internal/services/formatters/elixir/sobelow"
	"github.com/ZupIT/horusec/internal/services/formatters/generic/semgrep"
	"github.com/ZupIT/horusec/internal/services/formatters/go/gosec"
	"github.com/ZupIT/horusec/internal/services/formatters/hcl"
	"github.com/ZupIT/horusec/internal/services/formatters/java/horusecjava"
	"github.com/ZupIT/horusec/internal/services/formatters/javascript/horusecnodejs"
	"github.com/ZupIT/horusec/internal/services/formatters/javascript/npmaudit"
	"github.com/ZupIT/horusec/internal/services/formatters/javascript/yarnaudit"
	"github.com/ZupIT/horusec/internal/services/formatters/kotlin/horuseckotlin"
	"github.com/ZupIT/horusec/internal/services/formatters/leaks/gitleaks"
	"github.com/ZupIT/horusec/internal/services/formatters/leaks/horusecleaks"
	"github.com/ZupIT/horusec/internal/services/formatters/php/phpcs"
	"github.com/ZupIT/horusec/internal/services/formatters/python/bandit"
	"github.com/ZupIT/horusec/internal/services/formatters/python/safety"
	"github.com/ZupIT/horusec/internal/services/formatters/ruby/brakeman"
	"github.com/ZupIT/horusec/internal/services/formatters/ruby/bundler"
	"github.com/ZupIT/horusec/internal/services/formatters/shell/shellcheck"
	"github.com/ZupIT/horusec/internal/services/formatters/yaml/horuseckubernetes"
	horusecAPI "github.com/ZupIT/horusec/internal/services/horusec_api"
)

type Interface interface {
	AnalysisDirectory() (totalVulns int, err error)
}

type Analyser struct {
	monitor           *monitor.Monitor
	dockerSDK         docker.Interface
	analysis          *analysis.Analysis
	config            cliConfig.IConfig
	languageDetect    languageDetect.Interface
	printController   printresults.Interface
	horusecAPIService horusecAPI.IService
	formatterService  formatters.IService
}

func NewAnalyser(config cliConfig.IConfig) Interface {
	entity := &analysis.Analysis{ID: uuid.New()}
	dockerAPI := docker.NewDockerAPI(dockerClient.NewDockerClient(), config, entity.ID)
	return &Analyser{
		dockerSDK:         dockerAPI,
		analysis:          entity,
		config:            config,
		languageDetect:    languageDetect.NewLanguageDetect(config, entity.ID),
		printController:   printresults.NewPrintResults(entity, config),
		horusecAPIService: horusecAPI.NewHorusecAPIService(config),
		formatterService:  formatters.NewFormatterService(entity, dockerAPI, config, nil),
	}
}

func (a *Analyser) AnalysisDirectory() (totalVulns int, err error) {
	a.removeTrashByInterruptProcess()
	totalVulns, err = a.runAnalysis()
	a.removeHorusecFolder()
	return totalVulns, err
}

func (a *Analyser) removeTrashByInterruptProcess() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			a.removeHorusecFolder()
			log.Fatal()
		}
	}()
}

func (a *Analyser) removeHorusecFolder() {
	err := os.RemoveAll(a.config.GetProjectPath() + file.ReplacePathSeparator("/.horusec"))
	logger.LogErrorWithLevel(messages.MsgErrorRemoveAnalysisFolder, err)
	if !a.config.GetDisableDocker() {
		a.dockerSDK.DeleteContainersFromAPI()
	}
}

func (a *Analyser) runAnalysis() (totalVulns int, err error) {
	langs, err := a.languageDetect.LanguageDetect(a.config.GetProjectPath())
	if err != nil {
		return 0, err
	}

	a.setMonitor(monitor.NewMonitor())
	a.startDetectVulnerabilities(langs)
	return a.sendAnalysisAndStartPrintResults()
}

func (a *Analyser) sendAnalysisAndStartPrintResults() (int, error) {
	a.formatAnalysisToPrintAndSendToAPI()
	a.horusecAPIService.SendAnalysis(a.analysis)
	analysisSaved := a.horusecAPIService.GetAnalysis(a.analysis.ID)
	if analysisSaved != nil && analysisSaved.ID != uuid.Nil {
		a.analysis = analysisSaved
	}
	a.setFalsePositive()
	a.printController.SetAnalysis(a.analysis)
	return a.printController.StartPrintResults()
}

func (a *Analyser) formatAnalysisToPrintAndSendToAPI() {
	a.analysis = a.setAnalysisFinishedData()
	a.analysis = a.setupIDInAnalysisContents()
	a.analysis = a.sortVulnerabilitiesByCriticality()
	a.analysis = a.setDefaultVulnerabilityType()
	a.analysis = a.sortVulnerabilitiesByType()
	if !a.config.GetEnableInformationSeverity() {
		a.analysis = a.removeInfoVulnerabilities()
	}
}

func (a *Analyser) setMonitor(monitorToSet *monitor.Monitor) {
	a.monitor = monitorToSet
	a.formatterService.SetMonitor(monitorToSet)
}

func (a *Analyser) startDetectVulnerabilities(langs []languages.Language) {
	for _, language := range langs {
		for _, projectSubPath := range a.config.GetWorkDir().GetArrayByLanguage(language) {
			a.logProjectSubPath(language, projectSubPath)
			langFunc := a.mapDetectVulnerabilityByLanguage()[language]
			go langFunc(projectSubPath)
		}
	}

	a.runMonitorTimeout(a.config.GetTimeoutInSecondsAnalysis())
}

func (a *Analyser) runMonitorTimeout(monitorNumber int64) {
	if monitorNumber <= 0 {
		a.dockerSDK.DeleteContainersFromAPI()
		a.config.SetIsTimeout(true)
	}

	if !a.monitor.IsFinished() && !a.config.GetIsTimeout() {
		logger.LogInfoWithLevel(
			fmt.Sprintf(messages.MsgInfoMonitorTimeoutIn + strconv.Itoa(int(monitorNumber)) + "s"))
		time.Sleep(time.Duration(a.config.GetMonitorRetryInSeconds()) * time.Second)
		a.runMonitorTimeout(monitorNumber - a.config.GetMonitorRetryInSeconds())
	}
}

//nolint:funlen // all Languages is greater than 15
func (a *Analyser) mapDetectVulnerabilityByLanguage() map[languages.Language]func(string) {
	return map[languages.Language]func(string){
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
	}
}

func (a *Analyser) detectVulnerabilityCsharp(projectSubPath string) {
	const TotalProcess = 2
	a.monitor.AddProcess(TotalProcess)
	go horuseccsharp.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.CSharp)); err != nil {
		a.setErrorAndRemoveProcess(err, 1)
		return
	}

	go scs.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityLeaks(projectSubPath string) {
	const TotalProcess = 2
	a.monitor.AddProcess(TotalProcess)
	go horusecleaks.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	a.executeGitLeaks(projectSubPath)
}

func (a *Analyser) executeGitLeaks(projectSubPath string) {
	if a.config.GetEnableGitHistoryAnalysis() {
		logger.LogWarnWithLevel(messages.MsgWarnGitHistoryEnable)

		if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Leaks)); err != nil {
			a.setErrorAndRemoveProcess(err, 1)
			return
		}

		go gitleaks.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	} else {
		a.monitor.RemoveProcess(1)
	}
}

func (a *Analyser) detectVulnerabilityGo(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Go)); err != nil {
		a.setErrorAndRemoveProcess(err, 1)
		return
	}

	go gosec.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityJava(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)
	go horusecjava.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityKotlin(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)
	go horuseckotlin.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityJavascript(projectSubPath string) {
	const TotalProcess = 3
	a.monitor.AddProcess(TotalProcess)
	go horusecnodejs.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Javascript)); err != nil {
		a.setErrorAndRemoveProcess(err, 2)
		return
	}

	go yarnaudit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go npmaudit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityPython(projectSubPath string) {
	const TotalProcess = 2
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Python)); err != nil {
		a.setErrorAndRemoveProcess(err, 2)
		return
	}

	go bandit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go safety.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityRuby(projectSubPath string) {
	const TotalProcess = 2
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Ruby)); err != nil {
		a.setErrorAndRemoveProcess(err, 2)
		return
	}

	go brakeman.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go bundler.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityHCL(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.HCL)); err != nil {
		a.setErrorAndRemoveProcess(err, 1)
		return
	}

	go hcl.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityYaml(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)
	go horuseckubernetes.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityC(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.C)); err != nil {
		a.setErrorAndRemoveProcess(err, 1)
		return
	}

	go flawfinder.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityPHP(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.PHP)); err != nil {
		a.setErrorAndRemoveProcess(err, 1)
		return
	}

	go phpcs.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityGeneric(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Generic)); err != nil {
		a.setErrorAndRemoveProcess(err, 1)
		return
	}

	go semgrep.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityDart(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)
	go horusecDart.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityElixir(projectSubPath string) {
	const TotalProcess = 2
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Elixir)); err != nil {
		a.setErrorAndRemoveProcess(err, 2)
		return
	}

	go mixaudit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go sobelow.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityShell(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Shell)); err != nil {
		a.setErrorAndRemoveProcess(err, 1)
		return
	}

	go shellcheck.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) logProjectSubPath(language languages.Language, subPath string) {
	if subPath != "" {
		msg := fmt.Sprintf("Running %s in subpath: %s", language.ToString(), subPath)
		logger.LogDebugWithLevel(msg)
	}
}

func (a *Analyser) checkIfNoExistHashAndLog(list []string) {
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

func (a *Analyser) setFalsePositive() {
	a.analysis = a.SetFalsePositivesAndRiskAcceptInVulnerabilities(
		a.config.GetFalsePositiveHashes(), a.config.GetRiskAcceptHashes())

	a.checkIfNoExistHashAndLog(a.config.GetFalsePositiveHashes())
	a.checkIfNoExistHashAndLog(a.config.GetRiskAcceptHashes())
}

func (a *Analyser) setErrorAndRemoveProcess(err error, processNumber int) {
	a.setAnalysisError(err)
	a.monitor.RemoveProcess(processNumber)
}

func (a *Analyser) setAnalysisError(err error) {
	if err != nil {
		toAppend := ""
		if len(a.analysis.Errors) > 0 {
			a.analysis.Errors += "; " + err.Error()
			return
		}
		a.analysis.Errors += toAppend + err.Error()
	}
}
func (a *Analyser) getCustomOrDefaultImage(language languages.Language) string {
	if customImage := a.config.GetCustomImages()[language.GetCustomImagesKeyByLanguage()]; customImage != "" {
		return customImage
	}

	return fmt.Sprintf("%s/%s", images.DefaultRegistry, images.MapValues()[language])
}

func (a *Analyser) SetFalsePositivesAndRiskAcceptInVulnerabilities(
	listFalsePositive, listRiskAccept []string) *analysis.Analysis {
	for key := range a.analysis.AnalysisVulnerabilities {
		a.setVulnerabilityType(key, listFalsePositive, enumsVulnerability.FalsePositive)
		a.setVulnerabilityType(key, listRiskAccept, enumsVulnerability.RiskAccepted)
	}
	return a.analysis
}

func (a *Analyser) setVulnerabilityType(keyAnalysisVulnerabilities int,
	listToCheck []string, vulnerabilityType enumsVulnerability.Type) {
	currentHash := a.analysis.AnalysisVulnerabilities[keyAnalysisVulnerabilities].Vulnerability.VulnHash
	for _, flagVulnerabilityHash := range listToCheck {
		if flagVulnerabilityHash != "" && strings.TrimSpace(currentHash) == strings.TrimSpace(flagVulnerabilityHash) {
			a.analysis.AnalysisVulnerabilities[keyAnalysisVulnerabilities].Vulnerability.Type = vulnerabilityType
		}
	}
}

func (a *Analyser) setAnalysisFinishedData() *analysis.Analysis {
	a.analysis.FinishedAt = time.Now()

	if a.analysis.HasErrors() {
		a.analysis.Status = enumsAnalysis.Error
		return a.analysis
	}

	a.analysis.Status = enumsAnalysis.Success
	return a.analysis
}

func (a *Analyser) setupIDInAnalysisContents() *analysis.Analysis {
	for key := range a.analysis.AnalysisVulnerabilities {
		a.analysis.AnalysisVulnerabilities[key].SetCreatedAt()
		a.analysis.AnalysisVulnerabilities[key].SetAnalysisID(a.analysis.ID)
		a.analysis.AnalysisVulnerabilities[key].Vulnerability.VulnerabilityID = uuid.New()
	}
	return a.analysis
}

func (a *Analyser) sortVulnerabilitiesByCriticality() *analysis.Analysis {
	analysisVulnerabilities := a.getVulnerabilitiesBySeverity(severities.Critical)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.High)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Medium)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Low)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Unknown)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Info)...)
	a.analysis.AnalysisVulnerabilities = analysisVulnerabilities
	return a.analysis
}

func (a *Analyser) sortVulnerabilitiesByType() *analysis.Analysis {
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

func (a *Analyser) getVulnerabilitiesByType(
	vulnType enumsVulnerability.Type) (response []analysis.AnalysisVulnerabilities) {
	for index := range a.analysis.AnalysisVulnerabilities {
		if a.analysis.AnalysisVulnerabilities[index].Vulnerability.Type == vulnType {
			response = append(response, a.analysis.AnalysisVulnerabilities[index])
		}
	}
	return response
}

func (a *Analyser) getVulnerabilitiesBySeverity(
	search severities.Severity) (response []analysis.AnalysisVulnerabilities) {
	for index := range a.analysis.AnalysisVulnerabilities {
		if a.analysis.AnalysisVulnerabilities[index].Vulnerability.Severity == search {
			response = append(response, a.analysis.AnalysisVulnerabilities[index])
		}
	}
	return response
}

func (a *Analyser) setDefaultVulnerabilityType() *analysis.Analysis {
	for key := range a.analysis.AnalysisVulnerabilities {
		a.analysis.AnalysisVulnerabilities[key].Vulnerability.Type = enumsVulnerability.Vulnerability
	}
	return a.analysis
}

func (a *Analyser) removeInfoVulnerabilities() *analysis.Analysis {
	var vulnerabilities []analysis.AnalysisVulnerabilities

	for index := range a.analysis.AnalysisVulnerabilities {
		if a.analysis.AnalysisVulnerabilities[index].Vulnerability.Severity != severities.Info {
			vulnerabilities = append(vulnerabilities, a.analysis.AnalysisVulnerabilities[index])
		}
	}

	a.analysis.AnalysisVulnerabilities = vulnerabilities

	return a.analysis
}
