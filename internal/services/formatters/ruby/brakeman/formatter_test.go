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

package brakeman

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

		output := "{\"warnings\":[{\"warning_type\":\"Command Injection\",\"warning_code\":14,\"check_name\":\"Execute\",\"message\":\"Possible command injection\",\"file\":\"app/controllers/application_controller.rb\",\"line\":4,\"code\":\"system(\\\"ls #{options}\\\")\",\"render_path\":null,\"user_input\":\"options\",\"confidence\":\"Low\"},{\"warning_type\":\"Command Injection\",\"warning_code\":14,\"check_name\":\"Execute\",\"message\":\"Possible command injection\",\"file\":\"app/controllers/application_controller.rb\",\"line\":4,\"code\":\"system(\\\"ls #{options}\\\")\",\"render_path\":null,\"user_input\":\"options\",\"confidence\":\"Medium\"},{\"warning_type\":\"Command Injection\",\"warning_code\":14,\"check_name\":\"Execute\",\"message\":\"Possible command injection\",\"file\":\"app/controllers/application_controller.rb\",\"line\":4,\"code\":\"system(\\\"ls #{options}\\\")\",\"render_path\":null,\"user_input\":\"options\",\"confidence\":\"High\"},{\"warning_type\":\"Command Injection\",\"warning_code\":14,\"check_name\":\"Execute\",\"message\":\"Possible command injection\",\"file\":\"app/controllers/application_controller.rb\",\"line\":4,\"code\":\"system(\\\"ls #{options}\\\")\",\"render_path\":null,\"user_input\":\"options\",\"confidence\":\"Test\"}]}"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})

		assert.Len(t, analysis.AnalysisVulnerabilities, 4)
	})

	t.Run("Should success parse output empty to analysis", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		output := ""

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

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
			toolsconfig.ToolsConfigsStruct{Brakeman: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
