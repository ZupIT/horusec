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
	"path/filepath"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestParseOutput(t *testing.T) {
	t.Run("should add 3 vulnerability on analysis with no errors", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		newAnalysis := new(analysis.Analysis)

		cfg := config.New()
		cfg.ProjectPath = testutil.CreateHorusecAnalysisDirectory(t, newAnalysis, testutil.CsharpExample1)

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, newAnalysis.AnalysisVulnerabilities, 3)

		for _, v := range newAnalysis.AnalysisVulnerabilities {
			vuln := v.Vulnerability
			assert.Equal(t, tools.DotnetCli, vuln.SecurityTool)
			assert.Equal(t, languages.CSharp, vuln.Language)
			assert.Equal(t, confidence.High, vuln.Confidence)
			assert.NotEmpty(t, vuln.Details, "Exepcted not empty details")
			assert.NotContains(t, vuln.Details, "()")
			assert.NotEmpty(t, vuln.Code, "Expected not empty code")
			assert.Equal(
				t,
				filepath.Join("NetCoreVulnerabilities", "NetCoreVulnerabilities.csproj"),
				vuln.File,
				"Expected equals file name",
			)
			assert.NotEmpty(t, vuln.Line, "Expected not empty line")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")
		}
	})

	t.Run("should add no vulnerability and no errors on analysis", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		newAnalysis := new(analysis.Analysis)

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, config.New())
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, newAnalysis.AnalysisVulnerabilities, 0)
		assert.False(t, newAnalysis.HasErrors(), "Expected no errors on analysis")
	})

	t.Run("should add error from executing container on analysis", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		newAnalysis := new(analysis.Analysis)

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, config.New())
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, newAnalysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should add error on analysis when solution was not found", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(
			"A project or solution file could not be found", nil,
		)

		newAnalysis := new(analysis.Analysis)

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, config.New())
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, newAnalysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should not execute tool because it's ignored", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()

		newConfig := config.New()
		newConfig.ToolsConfig = toolsconfig.ToolsConfig{
			tools.DotnetCli: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(new(analysis.Analysis), dockerAPIControllerMock, newConfig)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}

var output = `
The following sources were used:
   https://api.nuget.org/v3/index.json

Project NetCoreVulnerabilities has the following vulnerable packages
[39;49m[34m   [netcoreapp3.1]: 
[39;49m   Top-level Package          [39;49m   [39;49m   Requested[39;49m   Resolved[39;49m   Severity[39;49m   Advisory URL                                     [39;49m
[39;49m   > adplug                   [39;49m   [39;49m   2.3.1    [39;49m   2.3.1   [39;49m[39;49m[31m   Critical[39;49m   https://github.com/advisories/GHSA-874w-m2v2-mj64[39;49m
[39;49m   > HtmlSanitizer            [39;49m   [39;49m   4.0.217  [39;49m   4.0.217 [39;49m   Low     [39;49m   https://github.com/advisories/GHSA-8j9v-h2vp-2hhv[39;49m
[39;49m   > Microsoft.ChakraCore     [39;49m   [39;49m   1.11.13  [39;49m   1.11.13 [39;49m[39;49m[31m   Critical[39;49m   https://github.com/advisories/GHSA-2wwc-w2gw-4329[39;49m
`
