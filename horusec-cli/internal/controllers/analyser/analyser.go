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
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/c/flawfinder"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/php/phpcs"

	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/csharp/horuseccsharp"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/javascript/horusecnodejs"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/yaml/horuseckubernetes"

	"github.com/google/uuid"

	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/java/horusecjava"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/kotlin/horuseckotlin"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	analysisUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/analysis"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	languageDetect "github.com/ZupIT/horusec/horusec-cli/internal/controllers/language_detect"
	"github.com/ZupIT/horusec/horusec-cli/internal/controllers/printresults"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	dockerClient "github.com/ZupIT/horusec/horusec-cli/internal/services/docker/client"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/csharp/scs"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/generic/semgrep"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/golang/gosec"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/hcl"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/javascript/eslint"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/javascript/npmaudit"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/javascript/yarnaudit"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/leaks/gitleaks"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/leaks/horusecleaks"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/python/bandit"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/python/safety"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/ruby/brakeman"
	horusecAPI "github.com/ZupIT/horusec/horusec-cli/internal/services/horusapi"
)

type Interface interface {
	AnalysisDirectory() (totalVulns int, err error)
}

type Analyser struct {
	monitor           *horusec.Monitor
	dockerSDK         docker.Interface
	analysis          *horusec.Analysis
	config            cliConfig.IConfig
	analysisUseCases  analysisUseCases.Interface
	languageDetect    languageDetect.Interface
	printController   printresults.Interface
	horusecAPIService horusecAPI.IService
	formatterService  formatters.IService
}

func NewAnalyser(config cliConfig.IConfig) Interface {
	useCases := analysisUseCases.NewAnalysisUseCases()
	analysis := useCases.NewAnalysisRunning()
	dockerAPI := docker.NewDockerAPI(dockerClient.NewDockerClient(), config, analysis.ID)
	return &Analyser{
		dockerSDK:         dockerAPI,
		analysis:          analysis,
		config:            config,
		languageDetect:    languageDetect.NewLanguageDetect(config, analysis.ID),
		analysisUseCases:  useCases,
		printController:   printresults.NewPrintResults(analysis, config),
		horusecAPIService: horusecAPI.NewHorusecAPIService(config),
		formatterService:  formatters.NewFormatterService(analysis, dockerAPI, config, nil),
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

	monitor := horusec.NewMonitor()

	a.setMonitor(monitor)
	a.startDetectVulnerabilities(langs)

	return a.sendAnalysisAndStartPrintResults()
}

func (a *Analyser) sendAnalysisAndStartPrintResults() (int, error) {
	a.analysis = a.analysis.SetAnalysisFinishedData().SetupIDInAnalysisContents().SortVulnerabilitiesByCriticality().
		SetDefaultVulnerabilityType().SortVulnerabilitiesByType()

	a.verifyIfInfoIsEnableAndSendAnalysis()
	analysisSaved := a.horusecAPIService.GetAnalysis(a.analysis.ID)
	if analysisSaved != nil && analysisSaved.ID != uuid.Nil {
		a.analysis = analysisSaved
	}
	a.setFalsePositive()
	a.printController.SetAnalysis(a.analysis)
	return a.printController.StartPrintResults()
}

func (a *Analyser) verifyIfInfoIsEnableAndSendAnalysis() {
	if !a.config.GetEnableInformationSeverity() {
		a.analysis.RemoveInfoVulnerabilities()
	}

	a.horusecAPIService.SendAnalysis(a.analysis)
}

func (a *Analyser) setMonitor(monitor *horusec.Monitor) {
	a.monitor = monitor
	a.formatterService.SetMonitor(monitor)
}

func (a *Analyser) startDetectVulnerabilities(langs []languages.Language) {
	for _, language := range langs {
		for _, projectSubPath := range a.config.GetWorkDir().GetArrayByLanguage(language) {
			if a.shouldAnalysePath(projectSubPath) {
				a.logProjectSubPath(language, projectSubPath)
				a.mapDetectVulnerabilityByLanguage()[language](projectSubPath)
			}
		}
	}

	a.runMonitorTimeout(a.config.GetTimeoutInSecondsAnalysis())
}

func (a *Analyser) runMonitorTimeout(monitor int64) {
	if monitor <= 0 {
		a.dockerSDK.DeleteContainersFromAPI()
		a.config.SetIsTimeout(true)
	}

	if !a.monitor.IsFinished() && !a.config.GetIsTimeout() {
		logger.LogInfoWithLevel(
			fmt.Sprintf(messages.MsgInfoMonitorTimeoutIn + strconv.Itoa(int(monitor)) + "s"))
		time.Sleep(time.Duration(a.config.GetMonitorRetryInSeconds()) * time.Second)
		a.runMonitorTimeout(monitor - a.config.GetMonitorRetryInSeconds())
	}
}

//nolint:funlen all Languages is greater than 15
func (a *Analyser) mapDetectVulnerabilityByLanguage() map[languages.Language]func(string) {
	return map[languages.Language]func(string){
		languages.CSharp:     a.detectVulnerabilityDotNet,
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
	}
}

func (a *Analyser) detectVulnerabilityDotNet(projectSubPath string) {
	a.monitor.AddProcess(2)
	go scs.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go horuseccsharp.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityLeaks(projectSubPath string) {
	a.monitor.AddProcess(1)
	go horusecleaks.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)

	if a.config.GetEnableGitHistoryAnalysis() {
		logger.LogWarnWithLevel(messages.MsgWarnGitHistoryEnable)
		a.monitor.AddProcess(1)
		go gitleaks.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	}
}

func (a *Analyser) detectVulnerabilityGo(projectSubPath string) {
	a.monitor.AddProcess(1)
	go gosec.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityJava(projectSubPath string) {
	a.monitor.AddProcess(1)
	go horusecjava.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityKotlin(projectSubPath string) {
	a.monitor.AddProcess(1)
	go horuseckotlin.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityJavascript(projectSubPath string) {
	a.monitor.AddProcess(4)
	go yarnaudit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go npmaudit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go eslint.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go horusecnodejs.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityPython(projectSubPath string) {
	a.monitor.AddProcess(2)
	go bandit.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
	go safety.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityRuby(projectSubPath string) {
	a.monitor.AddProcess(1)
	go brakeman.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityHCL(projectSubPath string) {
	a.monitor.AddProcess(1)
	go hcl.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityYaml(projectSubPath string) {
	a.monitor.AddProcess(1)
	go horuseckubernetes.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityC(projectSubPath string) {
	a.monitor.AddProcess(1)
	go flawfinder.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityPHP(projectSubPath string) {
	a.monitor.AddProcess(1)
	go phpcs.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) detectVulnerabilityGeneric(projectSubPath string) {
	a.monitor.AddProcess(1)
	go semgrep.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}

func (a *Analyser) shouldAnalysePath(projectSubPath string) bool {
	pathToFilter := a.config.GetFilterPath()
	if pathToFilter == "" {
		return true
	}

	pathToFilter = path.Join(a.config.GetProjectPath(), pathToFilter)
	fullProjectSubPath := path.Join(a.config.GetProjectPath(), projectSubPath)

	return strings.HasPrefix(fullProjectSubPath, pathToFilter)
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
	a.analysis = a.analysis.
		SetFalsePositivesAndRiskAcceptInVulnerabilities(
			a.config.GetFalsePositiveHashes(), a.config.GetRiskAcceptHashes())

	a.checkIfNoExistHashAndLog(a.config.GetFalsePositiveHashes())
	a.checkIfNoExistHashAndLog(a.config.GetRiskAcceptHashes())
}
