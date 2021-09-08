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

package bundler

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec/internal/entities/toolsconfig"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"

	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func TestParseOutput(t *testing.T) {
	t.Run("Should success parse output to analysis", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		output := "\u001B[31mName: \u001B[0mactionpack\n\u001B[31mVersion: \u001B[0m6.0.0\n\u001B[31mAdvisory: \u001B[0mCVE-2020-8164\n\u001B[31mCriticality: \u001B[0mUnknown\n\u001B[31mURL: \u001B[0mhttps://groups.google.com/forum/#!topic/rubyonrails-security/f6ioe4sdpbY\n\u001B[31mTitle: \u001B[0mPossible Strong Parameters Bypass in ActionPack\n\u001B[31mSolution: upgrade to \u001B[0m~> 5.2.4.3, >= 6.0.3.1\n\n\u001B[31mName: \u001B[0mactionpack\n\u001B[31mVersion: \u001B[0m6.0.0\n\u001B[31mAdvisory: \u001B[0mCVE-2020-8166\n\u001B[31mCriticality: \u001B[0mUnknown\n\u001B[31mURL: \u001B[0mhttps://groups.google.com/forum/#!topic/rubyonrails-security/NOjKiGeXUgw\n\u001B[31mTitle: \u001B[0mAbility to forge per-form CSRF tokens given a global CSRF token\n\u001B[31mSolution: upgrade to \u001B[0m~> 5.2.4.3, >= 6.0.3.1\n"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})

		assert.Len(t, analysis.AnalysisVulnerabilities, 2)
	})

	t.Run("Should return error when parsing invalid output", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid output", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})

	t.Run("Should return error when gem lock not found", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").
			Return("No such file or directory Errno::ENOENT", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})

	t.Run("Should return no vulnerabilities", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").
			Return("No vulnerabilities found", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})

	t.Run("Should return error when something went wrong in container", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{BundlerAudit: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
