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
	"strconv"
	"strings"
	"time"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"

	"github.com/ZupIT/horusec/internal/services/formatters/nginx/horusecnginx"

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
	"github.com/ZupIT/horusec/internal/services/formatters/dart/horusecdart"
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

type Analyzer struct {
	monitor           *monitor.Monitor
	dockerSDK         docker.Interface
	analysis          *analysis.Analysis
	config            cliConfig.IConfig
	languageDetect    languageDetect.Interface
	printController   printresults.Interface
	horusecAPIService horusecAPI.IService
	formatterService  formatters.IService
}

func NewAnalyzer(config cliConfig.IConfig) Interface {
	entity := &analysis.Analysis{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		Status:    enumsAnalysis.Running,
	}
	dockerAPI := docker.NewDockerAPI(dockerClient.NewDockerClient(), config, entity.ID)
	return &Analyzer{
		dockerSDK:         dockerAPI,
		analysis:          entity,
		config:            config,
		languageDetect:    languageDetect.NewLanguageDetect(config, entity.ID),
		printController:   printresults.NewPrintResults(entity, config),
		horusecAPIService: horusecAPI.NewHorusecAPIService(config),
		formatterService:  formatters.NewFormatterService(entity, dockerAPI, config, nil),
	}
}

func (a *Analyzer) AnalysisDirectory() (totalVulns int, err error) {
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
		a.dockerSDK.DeleteContainersFromAPI()
	}
}

func (a *Analyzer) runAnalysis() (totalVulns int, err error) {
	langs, err := a.languageDetect.LanguageDetect(a.config.GetProjectPath())
	if err != nil {
		return 0, err
	}

	a.setMonitor(monitor.NewMonitor())
	a.startDetectVulnerabilities(langs)
	return a.sendAnalysisAndStartPrintResults()
}

func (a *Analyzer) sendAnalysisAndStartPrintResults() (int, error) {
	a.formatAnalysisToSendToAPI()
	a.horusecAPIService.SendAnalysis(a.analysis)
	analysisSaved := a.horusecAPIService.GetAnalysis(a.analysis.ID)
	if analysisSaved != nil && analysisSaved.ID != uuid.Nil {
		a.analysis = analysisSaved
	}

	a.formatAnalysisToPrint()
	a.printController.SetAnalysis(a.analysis)
	return a.printController.StartPrintResults()
}

func (a *Analyzer) formatAnalysisToPrint() {
	a.analysis = a.setFalsePositive()
	if !a.config.GetEnableInformationSeverity() {
		a.analysis = a.removeInfoVulnerabilities()
	}
	a.analysis = a.removeVulnerabilitiesByTypes()
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

func (a *Analyzer) setMonitor(monitorToSet *monitor.Monitor) {
	a.monitor = monitorToSet
	a.formatterService.SetMonitor(monitorToSet)
}

func (a *Analyzer) startDetectVulnerabilities(langs []languages.Language) {
	for _, language := range langs {
		for _, projectSubPath := range a.config.GetWorkDir().GetArrayByLanguage(language) {
			a.logProjectSubPath(language, projectSubPath)
			langFunc := a.mapDetectVulnerabilityByLanguage()[language]
			if langFunc != nil {
				go langFunc(projectSubPath)
			}
		}
	}

	a.runMonitorTimeout(a.config.GetTimeoutInSecondsAnalysis())
}

func (a *Analyzer) runMonitorTimeout(monitorNumber int64) {
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
func (a *Analyzer) mapDetectVulnerabilityByLanguage() map[languages.Language]func(string) {
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
		languages.Nginx:      a.detectVulnerabilityNginx,
	}
}

func (a *Analyzer) detectVulnerabilityCsharp(projectSubPath string) {
	const TotalProcess = 2
	a.monitor.AddProcess(TotalProcess)
	go horuseccsharp.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.CSharp)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go scs.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityLeaks(projectSubPath string) {
	const TotalProcess = 2
	a.monitor.AddProcess(TotalProcess)
	go horusecleaks.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	a.executeGitLeaks(projectSubPath)
}

func (a *Analyzer) executeGitLeaks(projectSubPath string) {
	const TotalProcess = 1
	if a.config.GetEnableGitHistoryAnalysis() {
		logger.LogWarnWithLevel(messages.MsgWarnGitHistoryEnable)

		if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Leaks)); err != nil {
			a.setErrorAndRemoveProcess(err, TotalProcess)
			return
		}

		go gitleaks.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	} else {
		a.monitor.RemoveProcess(TotalProcess)
	}
}

func (a *Analyzer) detectVulnerabilityGo(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Go)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go gosec.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityJava(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)
	go horusecjava.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityKotlin(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)
	go horuseckotlin.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityNginx(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)
	go horusecnginx.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityJavascript(projectSubPath string) {
	const TotalProcess = 3
	a.monitor.AddProcess(TotalProcess)
	go horusecnodejs.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Javascript)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go yarnaudit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go npmaudit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityPython(projectSubPath string) {
	const TotalProcess = 2
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Python)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go bandit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go safety.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityRuby(projectSubPath string) {
	const TotalProcess = 2
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Ruby)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go brakeman.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go bundler.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityHCL(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.HCL)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go hcl.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityYaml(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)
	go horuseckubernetes.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityC(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.C)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go flawfinder.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityPHP(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.PHP)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go phpcs.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityGeneric(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Generic)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go semgrep.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityDart(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)
	go horusecdart.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityElixir(projectSubPath string) {
	const TotalProcess = 2
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Elixir)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go mixaudit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go sobelow.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyzer) detectVulnerabilityShell(projectSubPath string) {
	const TotalProcess = 1
	a.monitor.AddProcess(TotalProcess)

	if err := a.dockerSDK.PullImage(a.getCustomOrDefaultImage(languages.Shell)); err != nil {
		a.setErrorAndRemoveProcess(err, TotalProcess)
		return
	}

	go shellcheck.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
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

func (a *Analyzer) setErrorAndRemoveProcess(err error, processNumber int) {
	a.setAnalysisError(err)
	a.monitor.RemoveProcess(processNumber)
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
