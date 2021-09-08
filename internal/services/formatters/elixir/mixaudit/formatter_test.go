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

	"github.com/ZupIT/horusec/internal/entities/toolsconfig"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func getOutputString() string {
	return `{"pass":false,"vulnerabilities":[{"advisory":{"cve":"2019-15160","description":"The SweetXml (aka sweet_xml) package through 0.6.6 for Erlang and Elixir allows attackers to cause a denial of service (resource consumption) via an XML entity expansion attack with an inline DTD.\n","disclosure_date":"2019-08-19","id":"fb810971-a5c6-4268-9bd7-d931f72a87ec","package":"sweet_xml","patched_versions":[],"title":"Inline DTD allows XML bomb attack\n","unaffected_versions":[],"url":"https://github.com/kbrw/sweet_xml/issues/71"},"dependency":{"lockfile":"/src/mix.lock","package":"sweet_xml","version":"0.6.6"}}]}`
}

func TestStartCFlawfinder(t *testing.T) {
	t.Run("should success execute container and process output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		entity := &analysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := getOutputString()

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.NotEmpty(t, entity)
		assert.Len(t, entity.AnalysisVulnerabilities, 1)
	})

	t.Run("should return error when invalid output", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		entity := &analysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := ""

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("should return error when executing container", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		entity := &analysis.Analysis{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("should not execute tool because it's ignored", func(t *testing.T) {
		entity := &analysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}
		config.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{MixAudit: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
