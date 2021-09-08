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

package npmaudit

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

func TestStartNpmAudit(t *testing.T) {
	t.Run("Should parse output with no errors", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := "{\"advisories\":{\"1469\":{\"findings\":[{\"version\":\"0.6.6\",\"paths\":[\"express>qs\"]}],\"id\":1469,\"created\":\"2020-02-10T19:09:50.604Z\",\"updated\":\"2020-02-14T22:24:16.925Z\",\"deleted\":null,\"title\":\"Prototype Pollution Protection Bypass\",\"found_by\":{\"link\":\"\",\"name\":\"Unknown\",\"email\":\"\"},\"reported_by\":{\"link\":\"\",\"name\":\"Unknown\",\"email\":\"\"},\"module_name\":\"qs\",\"cves\":[\"CVE-2017-1000048\"],\"vulnerable_versions\":\"<6.0.4 || >=6.1.0 <6.1.2 || >=6.2.0 <6.2.3 || >=6.3.0 <6.3.2\",\"patched_versions\":\">=6.0.4 <6.1.0 || >=6.1.2 <6.2.0 || >=6.2.3 <6.3.0 || >=6.3.2\",\"overview\":\"Affected version of `qs` are vulnerable to Prototype Pollution because it is possible to bypass the protection. The `qs.parse` function fails to properly prevent an object's prototype to be altered when parsing arbitrary input. Input containing `[` or `]` may bypass the prototype pollution protection and alter the Object prototype. This allows attackers to override properties that will exist in all objects, which may lead to Denial of Service or Remote Code Execution in specific circumstances.\",\"recommendation\":\"Upgrade to 6.0.4, 6.1.2, 6.2.3, 6.3.2 or later.\",\"references\":\"- [GitHub Issue](https://github.com/ljharb/qs/issues/200)\\n- [Snyk Report](https://snyk.io/vuln/npm:qs:20170213)\",\"access\":\"public\",\"severity\":\"high\",\"cwe\":\"CWE-471\",\"metadata\":{\"module_type\":\"\",\"exploitability\":4,\"affected_components\":\"\"},\"url\":\"https://npmjs.com/advisories/1469\"}},\"metadata\":{\"vulnerabilities\":{\"info\":0,\"low\":8,\"moderate\":6,\"high\":7,\"critical\":0},\"dependencies\":23,\"devDependencies\":0,\"optionalDependencies\":0,\"totalDependencies\":23},\"runId\":\"7c3c5266-3f9d-4924-a8b7-93fad66e64e0\"}"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Equal(t, 1, len(analysis.AnalysisVulnerabilities))
	})
	t.Run("Should parse output with no errors", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := "{\"advisories\":{\"1469\":{\"findings\":[{\"version\":\"0.6.6\",\"paths\":[\"express>qs\"]}],\"id\":1469,\"created\":\"2020-02-10T19:09:50.604Z\",\"updated\":\"2020-02-14T22:24:16.925Z\",\"deleted\":null,\"title\":\"Prototype Pollution Protection Bypass\",\"found_by\":{\"link\":\"\",\"name\":\"Unknown\",\"email\":\"\"},\"reported_by\":{\"link\":\"\",\"name\":\"Unknown\",\"email\":\"\"},\"module_name\":\"qs\",\"cves\":[\"CVE-2017-1000048\"],\"vulnerable_versions\":\"<6.0.4 || >=6.1.0 <6.1.2 || >=6.2.0 <6.2.3 || >=6.3.0 <6.3.2\",\"patched_versions\":\">=6.0.4 <6.1.0 || >=6.1.2 <6.2.0 || >=6.2.3 <6.3.0 || >=6.3.2\",\"overview\":\"Affected version of `qs` are vulnerable to Prototype Pollution because it is possible to bypass the protection. The `qs.parse` function fails to properly prevent an object's prototype to be altered when parsing arbitrary input. Input containing `[` or `]` may bypass the prototype pollution protection and alter the Object prototype. This allows attackers to override properties that will exist in all objects, which may lead to Denial of Service or Remote Code Execution in specific circumstances.\",\"recommendation\":\"Upgrade to 6.0.4, 6.1.2, 6.2.3, 6.3.2 or later.\",\"references\":\"- [GitHub Issue](https://github.com/ljharb/qs/issues/200)\\n- [Snyk Report](https://snyk.io/vuln/npm:qs:20170213)\",\"access\":\"public\",\"severity\":\"high\",\"cwe\":\"CWE-471\",\"metadata\":{\"module_type\":\"\",\"exploitability\":4,\"affected_components\":\"\"},\"url\":\"https://npmjs.com/advisories/1469\"}},\"metadata\":{\"vulnerabilities\":{\"info\":0,\"low\":8,\"moderate\":6,\"high\":7,\"critical\":0},\"dependencies\":23,\"devDependencies\":0,\"optionalDependencies\":0,\"totalDependencies\":23},\"runId\":\"7c3c5266-3f9d-4924-a8b7-93fad66e64e0\"}"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Equal(t, 1, len(analysis.AnalysisVulnerabilities))
	})
	t.Run("Should parse output empty with no errors", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := ""

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Equal(t, 0, len(analysis.AnalysisVulnerabilities))
	})

	t.Run("Should parse output with not found error", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := "ERROR_PACKAGE_LOCK_NOT_FOUND"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Equal(t, 0, len(analysis.AnalysisVulnerabilities))
	})

	t.Run("Should return error when executing container", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Equal(t, 0, len(analysis.AnalysisVulnerabilities))
	})
	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{NpmAudit: toolsconfig.ToolConfig{IsToIgnore: true}},
		)
		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}

func TestParseOutputNpm(t *testing.T) {
	t.Run("Should return error when invalid output", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := Formatter{
			service,
		}

		err := formatter.parseOutput("invalid output", "")
		assert.Error(t, err)
		assert.Equal(t, 0, len(analysis.AnalysisVulnerabilities))
	})
}
