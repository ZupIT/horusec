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

package mixaudit

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

func TestStartCFlawfinder(t *testing.T) {
	t.Run("should add 1 vulnerability on analysis with no errors", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		entity := new(analysis.Analysis)

		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, newTestConfig(t, entity))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.NotEmpty(t, entity)
		assert.Len(t, entity.AnalysisVulnerabilities, 1)

		for _, v := range entity.AnalysisVulnerabilities {
			vuln := v.Vulnerability

			assert.Equal(t, tools.MixAudit, vuln.SecurityTool)
			assert.Equal(t, languages.Elixir, vuln.Language)
			assert.NotEmpty(t, vuln.Details, "Expected not empty details")
			assert.NotEmpty(t, vuln.Code, "Expected not empty code")
			assert.NotEmpty(t, vuln.File, "Expected not empty file name")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")

		}
	})

	t.Run("should not add error on analysis when parse empty output", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		entity := new(analysis.Analysis)

		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, newTestConfig(t, entity))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.False(t, entity.HasErrors(), "Expected no errors on analysis")
	})

	t.Run("should add error on analysis when get error executing container", func(t *testing.T) {
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
			tools.MixAudit: toolsconfig.Config{
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

const output = `
{
  "pass": false,
  "vulnerabilities": [
    {
      "advisory": {
        "cve": "2019-15160",
        "description": "The SweetXml (aka sweet_xml) package through 0.6.6 for Erlang and Elixir allows attackers to cause a denial of service (resource consumption) via an XML entity expansion attack with an inline DTD.\n",
        "disclosure_date": "2019-08-19",
        "id": "fb810971-a5c6-4268-9bd7-d931f72a87ec",
        "package": "sweet_xml",
        "patched_versions": [],
        "title": "Inline DTD allows XML bomb attack\n",
        "unaffected_versions": [],
        "url": "https://github.com/kbrw/sweet_xml/issues/71"
      },
      "dependency": {
        "lockfile": "/src/mix.lock",
        "package": "sweet_xml",
        "version": "0.6.6"
      }
    }
  ]
}
`
