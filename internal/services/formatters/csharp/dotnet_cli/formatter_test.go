// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package dotnetcli

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	analysisEntities "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"

	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func TestParseOutput(t *testing.T) {
	t.Run("should return 3 vulnerability with no errors", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		analysis := &analysisEntities.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := "The following sources were used:\n   https://api.nuget.org/v3/index.json\n\nProject " +
			"`NetCoreVulnerabilities` has the following vulnerable packages\n\u001B[39;49m\u001B[34m  " +
			" [netcoreapp3.1]: \n\u001B[39;49m   Top-level Package          \u001B[39;49m   \u001B[39;49m" +
			"   Requested\u001B[39;49m   Resolved\u001B[39;49m   Severity\u001B[39;49m   Advisory URL     " +
			"                                \u001B[39;49m\n\u001B[39;49m   > adplug                  " +
			" \u001B[39;49m   \u001B[39;49m   2.3.1    \u001B[39;49m   2.3.1   \u001B[39;49m\u001B[39;49m\u001B[31m " +
			"  Critical\u001B[39;49m   https://github.com/advisories/GHSA-874w-m2v2-mj64\u001B[39;49m\n\u001B[39;49m " +
			"  > Gw2Sharp                 \u001B[39;49m   \u001B[39;49m   0.3.0    \u001B[39;49m   0.3.0  " +
			" \u001B[39;49m   Low     \u001B[39;49m  " +
			" https://github.com/advisories/GHSA-4vr3-9v7h-5f8v\u001B[39;49m\n\u001B[39;49m   > log4net " +
			"                 \u001B[39;49m   \u001B[39;49m   2.0.9    \u001B[39;49m   2.0.9  " +
			" \u001B[39;49m\u001B[39;49m\u001B[31m   Critical\u001B[39;49m   " +
			"https://github.com/advisories/GHSA-2cwj-8chv-9pp9\u001B[39;49m\n"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 3)
	})

	t.Run("should return no vulnerability with no errors", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		analysis := &analysisEntities.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})

	t.Run("should return error executing container", func(t *testing.T) {
		analysis := &analysisEntities.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(
			"", errors.New("test"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.NotEmpty(t, analysis.Errors)
	})

	t.Run("should return error when solution was not found", func(t *testing.T) {
		analysis := &analysisEntities.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(
			"A project or solution file could not be found", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.NotEmpty(t, analysis.Errors)
	})

	t.Run("should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &analysisEntities.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}
		config.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{DotnetCli: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
