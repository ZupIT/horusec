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

package shellcheck

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
		config.EnableShellCheck = true
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		output := "[{\"file\":\"./src/windows/formula/formula.bat\",\"line\":1,\"endLine\":1,\"column\":1,\"endColumn\":1,\"level\":\"error\",\"code\":2148,\"message\":\"Tips depend on target shell and yours is unknown. Add a shebang or a 'shell' directive.\",\"fix\":null},{\"file\":\"./src/main.bat\",\"line\":1,\"endLine\":1,\"column\":1,\"endColumn\":1,\"level\":\"error\",\"code\":2148,\"message\":\"Tips depend on target shell and yours is unknown. Add a shebang or a 'shell' directive.\",\"fix\":null},{\"file\":\"./src/main.bat\",\"line\":3,\"endLine\":3,\"column\":13,\"endColumn\":13,\"level\":\"info\",\"code\":1001,\"message\":\"This \\\\f will be a regular 'f' in this context.\",\"fix\":null},{\"file\":\"./src/main.bat\",\"line\":3,\"endLine\":3,\"column\":21,\"endColumn\":21,\"level\":\"info\",\"code\":1001,\"message\":\"This \\\\f will be a regular 'f' in this context.\",\"fix\":null},{\"file\":\"./build.bat\",\"line\":1,\"endLine\":1,\"column\":1,\"endColumn\":1,\"level\":\"error\",\"code\":2148,\"message\":\"Tips depend on target shell and yours is unknown. Add a shebang or a 'shell' directive.\",\"fix\":null},{\"file\":\"./build.bat\",\"line\":13,\"endLine\":13,\"column\":3,\"endColumn\":18,\"level\":\"warning\",\"code\":2164,\"message\":\"Use 'cd ... || exit' or 'cd ... || return' in case cd fails.\",\"fix\":{\"replacements\":[{\"line\":13,\"endLine\":13,\"precedence\":5,\"insertionPoint\":\"beforeStart\",\"column\":18,\"replacement\":\" || exit\",\"endColumn\":18}]}},{\"file\":\"./build.bat\",\"line\":25,\"endLine\":25,\"column\":3,\"endColumn\":8,\"level\":\"info\",\"code\":2103,\"message\":\"Use a ( subshell ) to avoid having to cd back.\",\"fix\":null},{\"file\":\"./build.bat\",\"line\":31,\"endLine\":31,\"column\":8,\"endColumn\":10,\"level\":\"error\",\"code\":2242,\"message\":\"Can only exit with status 0-255. Other data should be written to stdout/stderr.\",\"fix\":null},{\"file\":\"./src/unix/formula/formula.sh\",\"line\":34,\"endLine\":34,\"column\":70,\"endColumn\":83,\"level\":\"info\",\"code\":2086,\"message\":\"Double quote to prevent globbing and word splitting.\",\"fix\":{\"replacements\":[{\"line\":34,\"endLine\":34,\"precedence\":11,\"insertionPoint\":\"afterEnd\",\"column\":70,\"replacement\":\"\\\"\",\"endColumn\":70},{\"line\":34,\"endLine\":34,\"precedence\":11,\"insertionPoint\":\"beforeStart\",\"column\":83,\"replacement\":\"\\\"\",\"endColumn\":83}]}},{\"file\":\"./src/unix/formula/formula.sh\",\"line\":44,\"endLine\":44,\"column\":24,\"endColumn\":33,\"level\":\"info\",\"code\":2086,\"message\":\"Double quote to prevent globbing and word splitting.\",\"fix\":{\"replacements\":[{\"line\":44,\"endLine\":44,\"precedence\":21,\"insertionPoint\":\"afterEnd\",\"column\":24,\"replacement\":\"\\\"\",\"endColumn\":24},{\"line\":44,\"endLine\":44,\"precedence\":21,\"insertionPoint\":\"beforeStart\",\"column\":33,\"replacement\":\"\\\"\",\"endColumn\":33}]}}]"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})

		assert.Equal(t, 7, len(analysis.AnalysisVulnerabilities))
	})
	t.Run("Should success parse output empty to analysis", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}

		config := &cliConfig.Config{}
		config.EnableShellCheck = true
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})

		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})
	t.Run("Should error rails not found when parse output to analysis", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}

		config := &cliConfig.Config{}
		config.EnableShellCheck = true
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		output := "Please supply the path to a Rails application"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})

		assert.NotEmpty(t, analysis.Errors)
	})

	t.Run("Should return error when parsing invalid output", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}

		config := &cliConfig.Config{}
		config.EnableShellCheck = true
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid output", nil)

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
		config.EnableShellCheck = true
		config.WorkDir = &workdir.WorkDir{}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.EnableShellCheck = true
		config.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{ShellCheck: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
