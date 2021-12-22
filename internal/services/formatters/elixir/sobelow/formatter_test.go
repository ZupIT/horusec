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

package sobelow

import (
	"errors"
	"path/filepath"
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

func TestSobelowStartAnalysis(t *testing.T) {
	t.Run("should add 4 vulnerabilities on analysis with no errors", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		entity := new(analysis.Analysis)

		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, newTestConfig(t, entity))
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.Len(t, entity.AnalysisVulnerabilities, 4)

		for _, v := range entity.AnalysisVulnerabilities {
			vuln := v.Vulnerability

			assert.Equal(t, tools.Sobelow, vuln.SecurityTool)
			assert.Equal(t, languages.Elixir, vuln.Language)
			assert.NotEmpty(t, vuln.Details, "Expected not empty details")
			assert.NotEmpty(t, vuln.File, "Expected not empty file name")
			assert.NotEmpty(t, vuln.Line, "Expected not empty line")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")

		}
	})

	t.Run("should not add error on analysis when empty output", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		analysis := new(analysis.Analysis)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.False(t, analysis.HasErrors(), "Expected no errors on analysis")
	})

	t.Run("should return error when executing container", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		entity := new(analysis.Analysis)

		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, newTestConfig(t, entity))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, entity.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should not execute tool because it's ignored", func(t *testing.T) {
		entity := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()

		config := config.New()
		config.ToolsConfig = toolsconfig.ToolsConfig{
			tools.Sobelow: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}

func newTestConfig(t *testing.T, analysiss *analysis.Analysis) *config.Config {
	cfg := config.New()
	cfg.ProjectPath = testutil.CreateHorusecAnalysisDirectory(t, analysiss, testutil.ElixirExample)
	return cfg
}

var output = `
		[31m[+][0m Config.CSP: Missing Content-Security-Policy - ` + filepath.Join("lib", "built_with_elixir_web", "router") + `.ex:9
		[31m[+][0m Config.Secrets: Hardcoded Secret - ` + filepath.Join("config", "prod") + `.exs:1
		[31m[+][0m Config.HTTPS: HTTPS Not Enabled - ` + filepath.Join("config", "dev") + `.exs:1
		[32m[+][0m XSS.Raw: XSS - ` + filepath.Join("lib", "built_with_elixir_web", "templates", "layout", "app.html") + `.eex:17
`
