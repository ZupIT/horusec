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

package phpcs

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStartCFlawfinder(t *testing.T) {
	t.Run("should success execute container and process output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &horusec.Analysis{}
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		output := "{ \"files\":{ \"\\/src\\/XSS\\/XSS_level5.php\":{ \"errors\":1, \"warnings\":4, \"messages\":[ { \"message\":\"User input detetected with $_SERVER.\", \"source\":\"PHPCS_SecurityAudit.Drupal7.UserInputWatch.D7UserInWaWarn\", \"severity\":5, \"fixable\":false, \"type\":\"WARNING\", \"line\":14, \"column\":39 }, { \"message\":\"Easy XSS detected because of direct user input with $_SERVER on echo\", \"source\":\"PHPCS_SecurityAudit.BadFunctions.EasyXSS.EasyXSSerr\", \"severity\":5, \"fixable\":false, \"type\":\"ERROR\", \"line\":14, \"column\":39 } ] } } }"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.NotEmpty(t, analysis)
		assert.Len(t, analysis.AnalysisVulnerabilities, 1)
	})

	t.Run("should return error when invalid output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &horusec.Analysis{}
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		output := ""

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("should return error when executing container", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		analysis := &horusec.Analysis{}
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})
	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.SetToolsToIgnore([]string{"GoSec", "SecurityCodeScan", "Brakeman", "Safety", "Bandit", "NpmAudit", "YarnAudit", "SpotBugs", "HorusecKotlin", "HorusecJava", "HorusecLeaks", "GitLeaks", "TfSec", "Semgrep", "HorusecCsharp", "HorusecKubernetes", "Eslint", "HorusecNodeJS", "Flawfinder", "PhpCS", "Eslint", "HorusecNodeJS", "Flawfinder", "PhpCS", "phpcs"})
		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
