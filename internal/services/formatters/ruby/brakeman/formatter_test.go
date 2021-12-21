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

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestParseBrakemanOutput(t *testing.T) {
	t.Run("Should success parse output to analysis", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputMock, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 4)

		for _, v := range analysis.AnalysisVulnerabilities {
			vuln := v.Vulnerability

			assert.Equal(t, tools.Brakeman, vuln.SecurityTool)
			assert.Equal(t, languages.Ruby, vuln.Language)
			assert.NotEmpty(t, vuln.Details, "Expected not empty details")
			assert.NotEmpty(t, vuln.Code, "Expected not empty code")
			assert.NotEmpty(t, vuln.File, "Expected not empty file name")
			assert.NotEmpty(t, vuln.Line, "Expected not empty line")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")

		}
	})

	t.Run("Should success parse output empty to analysis", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})

	t.Run("Should add error rails not found on analysis when parse output to analysis", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")

		output := "Please supply the path to a Rails application"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.NotEmpty(t, analysis.Errors)
	})

	t.Run("Should add error on analysis when parsing invalid output", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid output", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should add error on analysis when something went wrong in container", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()

		cfg := config.New()
		cfg.ToolsConfig = toolsconfig.ToolsConfig{
			tools.Brakeman: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")
	})
}

func newTestConfig(t *testing.T, analysis *analysis.Analysis) *config.Config {
	cfg := config.New()
	cfg.ProjectPath = testutil.CreateHorusecAnalysisDirectory(t, analysis, testutil.RubyExample)
	return cfg
}

const outputMock = `
{
  "warnings": [
    {
      "warning_type": "Command Injection",
      "warning_code": 14,
      "check_name": "Execute",
      "message": "Possible command injection",
      "file": "app/controllers/application_controller.rb",
      "line": 4,
      "code": "system(\"ls #{options}\")",
      "render_path": null,
      "user_input": "options",
      "confidence": "Low"
    },
    {
      "warning_type": "Command Injection",
      "warning_code": 14,
      "check_name": "Execute",
      "message": "Possible command injection",
      "file": "app/controllers/application_controller.rb",
      "line": 4,
      "code": "system(\"ls #{options}\")",
      "render_path": null,
      "user_input": "options",
      "confidence": "Medium"
    },
    {
      "warning_type": "Command Injection",
      "warning_code": 14,
      "check_name": "Execute",
      "message": "Possible command injection",
      "file": "app/controllers/application_controller.rb",
      "line": 4,
      "code": "system(\"ls #{options}\")",
      "render_path": null,
      "user_input": "options",
      "confidence": "High"
    },
    {
      "warning_type": "Command Injection",
      "warning_code": 14,
      "check_name": "Execute",
      "message": "Possible command injection",
      "file": "app/controllers/application_controller.rb",
      "line": 4,
      "code": "system(\"ls #{options}\")",
      "render_path": null,
      "user_input": "options",
      "confidence": "Test"
    }
  ]
}
`
