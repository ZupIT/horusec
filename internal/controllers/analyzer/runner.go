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
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/briandowns/spinner"
	"github.com/sirupsen/logrus"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/docker"
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
	"github.com/ZupIT/horusec/internal/services/formatters/javascript/horusecjavascript"
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
)

const spinnerLoadingDelay = 200 * time.Millisecond

// detectVulnerabilityFn is a func that detect vulnerabilities on path.
// detectVulnerabilityFn funcs run all in parallel, so a WaitGroup is required
// to synchronize states of running analysis.
//
// detectVulnerabilityFn funcs can also spawn other detectVulnerabilityFn funcs
// just passing the received WaitGroup to underlying funcs.
//
// Note that the argument path is a work dir path and not the project path, so this
// value can be empty.
type detectVulnerabilityFn func(wg *sync.WaitGroup, path string) error

// runner is responsible to orchestrate all executions.
//
// For each language founded on project path, runner will run an analysis using
// the appropriate tool.
type runner struct {
	loading   *spinner.Spinner
	config    *config.Config
	docker    docker.Docker
	formatter formatters.IService
}

func newRunner(cfg *config.Config, analysiss *analysis.Analysis, dockerAPI *docker.API) *runner {
	return &runner{
		loading:   newScanLoading(cfg),
		formatter: formatters.NewFormatterService(analysiss, dockerAPI, cfg),
		config:    cfg,
		docker:    dockerAPI,
	}
}

// run handle execution of all analysis in parallel
//
// nolint:funlen,gocyclo
func (r *runner) run(langs []languages.Language) []error {
	r.removeTrashByInterruptProcess()
	defer r.removeHorusecFolder()

	var (
		wg     sync.WaitGroup
		errors []error
		mutex  = new(sync.Mutex)
		done   = make(chan struct{})
	)

	funcs := r.detectVulnerabilityFuncs()

	r.loading.Start()

	go func() {
		defer close(done)
		for _, language := range langs {
			for _, subPath := range r.config.WorkDir.PathsOfLanguage(language) {
				projectSubPath := subPath
				r.logProjectSubPath(language, projectSubPath)

				if fn, exist := funcs[language]; exist {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if err := fn(&wg, projectSubPath); err != nil {
							mutex.Lock()
							errors = append(errors, err)
							mutex.Unlock()
						}
					}()
				}
			}
		}
		wg.Wait()
	}()

	timeout := time.After(time.Duration(r.config.TimeoutInSecondsAnalysis) * time.Second)
	for {
		select {
		case <-done:
			r.loading.Stop()
			return errors
		case <-timeout:
			r.docker.DeleteContainersFromAPI()
			r.config.IsTimeout = true
			r.loading.Stop()
			return errors
		}
	}
}

// detectVulnerabilityFuncs returns a map of language and a function
// that detect vulnerabilities on some path.
//
//nolint:funlen
func (r *runner) detectVulnerabilityFuncs() map[languages.Language]detectVulnerabilityFn {
	return map[languages.Language]detectVulnerabilityFn{
		languages.CSharp:     r.detectVulnerabilityCsharp,
		languages.Leaks:      r.detectVulnerabilityLeaks,
		languages.Go:         r.detectVulnerabilityGo,
		languages.Java:       r.detectVulnerabilityJava,
		languages.Kotlin:     r.detectVulnerabilityKotlin,
		languages.Javascript: r.detectVulnerabilityJavascript,
		languages.Python:     r.detectVulnerabilityPython,
		languages.Ruby:       r.detectVulnerabilityRuby,
		languages.HCL:        r.detectVulnerabilityHCL,
		languages.Generic:    r.detectVulnerabilityGeneric,
		languages.Yaml:       r.detectVulnerabilityYaml,
		languages.C:          r.detectVulnerabilityC,
		languages.PHP:        r.detectVulnerabilityPHP,
		languages.Dart:       r.detectVulnerabilityDart,
		languages.Elixir:     r.detectVulnerabilityElixir,
		languages.Shell:      r.detectVulnerabilityShell,
		languages.Nginx:      r.detectVulnerabilityNginx,
		languages.Swift:      r.detectVulneravilitySwift,
	}
}

func (r *runner) detectVulneravilitySwift(_ *sync.WaitGroup, projectSubPath string) error {
	horusecswift.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityCsharp(wg *sync.WaitGroup, projectSubPath string) error {
	spawn(wg, horuseccsharp.NewFormatter(r.formatter), projectSubPath)

	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.CSharp)); err != nil {
		return err
	}

	spawn(wg, scs.NewFormatter(r.formatter), projectSubPath)
	dotnetcli.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityLeaks(wg *sync.WaitGroup, projectSubPath string) error {
	spawn(wg, horusecleaks.NewFormatter(r.formatter), projectSubPath)

	if r.config.EnableGitHistoryAnalysis {
		if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.Leaks)); err != nil {
			return err
		}
		gitleaks.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	}

	return nil
}

func (r *runner) detectVulnerabilityGo(wg *sync.WaitGroup, projectSubPath string) error {
	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.Go)); err != nil {
		return err
	}

	spawn(wg, gosec.NewFormatter(r.formatter), projectSubPath)
	nancy.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityJava(_ *sync.WaitGroup, projectSubPath string) error {
	horusecjava.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityKotlin(_ *sync.WaitGroup, projectSubPath string) error {
	horuseckotlin.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityNginx(_ *sync.WaitGroup, projectSubPath string) error {
	horusecnginx.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityJavascript(wg *sync.WaitGroup, projectSubPath string) error {
	spawn(wg, horusecjavascript.NewFormatter(r.formatter), projectSubPath)
	spawn(wg, horusecjavascript.NewSemanticFormatter(r.formatter), projectSubPath)

	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.Javascript)); err != nil {
		return err
	}
	spawn(wg, yarnaudit.NewFormatter(r.formatter), projectSubPath)
	npmaudit.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityPython(wg *sync.WaitGroup, projectSubPath string) error {
	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.Python)); err != nil {
		return err
	}
	spawn(wg, bandit.NewFormatter(r.formatter), projectSubPath)
	safety.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityRuby(wg *sync.WaitGroup, projectSubPath string) error {
	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.Ruby)); err != nil {
		return err
	}
	spawn(wg, brakeman.NewFormatter(r.formatter), projectSubPath)
	bundler.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityHCL(wg *sync.WaitGroup, projectSubPath string) error {
	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.HCL)); err != nil {
		return err
	}
	spawn(wg, tfsec.NewFormatter(r.formatter), projectSubPath)
	checkov.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityYaml(_ *sync.WaitGroup, projectSubPath string) error {
	horuseckubernetes.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityC(_ *sync.WaitGroup, projectSubPath string) error {
	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.C)); err != nil {
		return err
	}
	flawfinder.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityPHP(_ *sync.WaitGroup, projectSubPath string) error {
	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.PHP)); err != nil {
		return err
	}
	phpcs.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityGeneric(wg *sync.WaitGroup, projectSubPath string) error {
	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.Generic)); err != nil {
		return err
	}

	spawn(wg, trivy.NewFormatter(r.formatter), projectSubPath)
	spawn(wg, semgrep.NewFormatter(r.formatter), projectSubPath)
	dependencycheck.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityDart(_ *sync.WaitGroup, projectSubPath string) error {
	horusecdart.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityElixir(wg *sync.WaitGroup, projectSubPath string) error {
	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.Elixir)); err != nil {
		return err
	}
	spawn(wg, mixaudit.NewFormatter(r.formatter), projectSubPath)
	sobelow.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) detectVulnerabilityShell(_ *sync.WaitGroup, projectSubPath string) error {
	if err := r.docker.PullImage(r.getCustomOrDefaultImage(languages.Shell)); err != nil {
		return err
	}
	shellcheck.NewFormatter(r.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (r *runner) getCustomOrDefaultImage(language languages.Language) string {
	// Images can be set to empty on config file, so we need to use only if its not empty.
	// If its empty we return the default value.
	if customImage := r.config.CustomImages[language]; customImage != "" {
		return customImage
	}
	return path.Join(images.DefaultRegistry, images.MapValues()[language])
}

func (r *runner) logProjectSubPath(language languages.Language, subPath string) {
	if subPath != "" {
		msg := fmt.Sprintf("Running %s in subpath: %s", language.ToString(), subPath)
		logger.LogDebugWithLevel(msg)
	}
}

func (r *runner) removeHorusecFolder() {
	err := os.RemoveAll(filepath.Join(r.config.ProjectPath, ".horusec"))
	logger.LogErrorWithLevel(messages.MsgErrorRemoveAnalysisFolder, err)
	if !r.config.DisableDocker {
		r.docker.DeleteContainersFromAPI()
	}
}

func (r *runner) removeTrashByInterruptProcess() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			r.removeHorusecFolder()
			os.Exit(1)
		}
	}()
}

func spawn(wg *sync.WaitGroup, f formatters.IFormatter, src string) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		f.StartAnalysis(src)
	}()
}

func newScanLoading(cfg *config.Config) *spinner.Spinner {
	loading := spinner.New(spinner.CharSets[11], spinnerLoadingDelay)
	loading.Suffix = messages.MsgInfoAnalysisLoading

	if cfg.LogLevel == logrus.DebugLevel.String() || cfg.LogLevel == logrus.TraceLevel.String() {
		loading.Writer = io.Discard
	}

	return loading
}
