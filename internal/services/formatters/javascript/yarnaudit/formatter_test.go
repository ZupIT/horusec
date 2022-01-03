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

package yarnaudit

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

func TestYarnAuditParseOutput(t *testing.T) {
	t.Run("should add 1 vulnerabilities on analysis with no errors", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 1)

		for _, v := range analysis.AnalysisVulnerabilities {
			vuln := v.Vulnerability

			assert.Equal(t, tools.YarnAudit, vuln.SecurityTool)
			assert.Equal(t, languages.Javascript, vuln.Language)
			assert.NotEmpty(t, vuln.Details, "Expected not empty details")
			assert.NotEmpty(t, vuln.Code, "Expected not empty code")
			assert.NotEmpty(t, vuln.File, "Expected not empty file name")
			assert.NotEmpty(t, vuln.Line, "Expected not empty line")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")

		}
	})

	t.Run("Should parse output empty with no errors", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
		assert.False(t, analysis.HasErrors(), "Expected no errors on analysis")
	})

	t.Run("Should add error on analysis with not found error", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("ERROR_YARN_LOCK_NOT_FOUND", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should add error on analysis with audit error", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("ERROR_RUNNING_YARN_AUDIT", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should add error on analysis when parse invalid output", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected no errors on analysis")
	})

	t.Run("should add error of executing container on analysis", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})
	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := new(analysis.Analysis)
		dockerAPIControllerMock := testutil.NewDockerMock()

		cfg := newTestConfig(t, analysis)
		cfg.ToolsConfig = toolsconfig.ToolsConfig{
			tools.YarnAudit: toolsconfig.Config{
				IsToIgnore: true,
			},
		}
		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")
	})
}

func newTestConfig(t *testing.T, analysiss *analysis.Analysis) *config.Config {
	cfg := config.New()
	cfg.ProjectPath = testutil.CreateHorusecAnalysisDirectory(t, analysiss, testutil.JavaScriptExample2)
	return cfg
}

const output = `
{
  "advisories": [
    {
      "findings": [
        {
          "version": "4.0.0",
          "paths": [
            "express"
          ]
        }
      ],
      "id": 8,
      "created": "2015-10-17T19:41:46.382Z",
      "updated": "2018-02-22T21:55:47.925Z",
      "deleted": null,
      "title": "No Charset in Content-Type Header",
      "found_by": {
        "name": "Paweł Hałdrzyński"
      },
      "reported_by": {
        "name": "Paweł Hałdrzyński"
      },
      "module_name": "express",
      "cves": [
        "CVE-2014-6393"
      ],
      "vulnerable_versions": "<3.11 || >= 4 <4.5",
      "patched_versions": ">=3.11 <4 || >=4.5",
      "overview": "Vulnerable versions of express do not specify a charset field in the content-type header while displaying 400 level response messages. The lack of enforcing user's browser to set correct charset, could be leveraged by an attacker to perform a cross-site scripting attack, using non-standard encodings, like UTF-7.",
      "recommendation": "For express 3.x, update express to version 3.11 or later.\nFor express 4.x, update express to version 4.5 or later. ",
      "references": "",
      "access": "public",
      "severity": "low",
      "cwe": "CWE-79",
      "metadata": {
        "module_type": "Network.Library",
        "exploitability": 2,
        "affected_components": ""
      },
      "url": "https://npmjs.com/advisories/8"
    },
    {
      "findings": [
        {
          "version": "4.0.0",
          "paths": [
            "express"
          ]
        }
      ],
      "id": 8,
      "created": "2015-10-17T19:41:46.382Z",
      "updated": "2018-02-22T21:55:47.925Z",
      "deleted": null,
      "title": "No Charset in Content-Type Header",
      "found_by": {
        "name": "Paweł Hałdrzyński"
      },
      "reported_by": {
        "name": "Paweł Hałdrzyński"
      },
      "module_name": "express",
      "cves": [
        "CVE-2014-6393"
      ],
      "vulnerable_versions": "<3.11 || >= 4 <4.5",
      "patched_versions": ">=3.11 <4 || >=4.5",
      "overview": "Vulnerable versions of express do not specify a charset field in the content-type header while displaying 400 level response messages. The lack of enforcing user's browser to set correct charset, could be leveraged by an attacker to perform a cross-site scripting attack, using non-standard encodings, like UTF-7.",
      "recommendation": "For express 3.x, update express to version 3.11 or later.\nFor express 4.x, update express to version 4.5 or later. ",
      "references": "",
      "access": "public",
      "severity": "moderate",
      "cwe": "CWE-79",
      "metadata": {
        "module_type": "Network.Library",
        "exploitability": 2,
        "affected_components": ""
      },
      "url": "https://npmjs.com/advisories/8"
    },
    {
      "findings": [
        {
          "version": "4.0.0",
          "paths": [
            "express"
          ]
        }
      ],
      "id": 8,
      "created": "2015-10-17T19:41:46.382Z",
      "updated": "2018-02-22T21:55:47.925Z",
      "deleted": null,
      "title": "No Charset in Content-Type Header",
      "found_by": {
        "name": "Paweł Hałdrzyński"
      },
      "reported_by": {
        "name": "Paweł Hałdrzyński"
      },
      "module_name": "express",
      "cves": [
        "CVE-2014-6393"
      ],
      "vulnerable_versions": "<3.11 || >= 4 <4.5",
      "patched_versions": ">=3.11 <4 || >=4.5",
      "overview": "Vulnerable versions of express do not specify a charset field in the content-type header while displaying 400 level response messages. The lack of enforcing user's browser to set correct charset, could be leveraged by an attacker to perform a cross-site scripting attack, using non-standard encodings, like UTF-7.",
      "recommendation": "For express 3.x, update express to version 3.11 or later.\nFor express 4.x, update express to version 4.5 or later. ",
      "references": "",
      "access": "public",
      "severity": "high",
      "cwe": "CWE-79",
      "metadata": {
        "module_type": "Network.Library",
        "exploitability": 2,
        "affected_components": ""
      },
      "url": "https://npmjs.com/advisories/8"
    },
    {
      "findings": [
        {
          "version": "4.0.0",
          "paths": [
            "express"
          ]
        }
      ],
      "id": 8,
      "created": "2015-10-17T19:41:46.382Z",
      "updated": "2018-02-22T21:55:47.925Z",
      "deleted": null,
      "title": "No Charset in Content-Type Header",
      "found_by": {
        "name": "Paweł Hałdrzyński"
      },
      "reported_by": {
        "name": "Paweł Hałdrzyński"
      },
      "module_name": "express",
      "cves": [
        "CVE-2014-6393"
      ],
      "vulnerable_versions": "<3.11 || >= 4 <4.5",
      "patched_versions": ">=3.11 <4 || >=4.5",
      "overview": "Vulnerable versions of express do not specify a charset field in the content-type header while displaying 400 level response messages. The lack of enforcing user's browser to set correct charset, could be leveraged by an attacker to perform a cross-site scripting attack, using non-standard encodings, like UTF-7.",
      "recommendation": "For express 3.x, update express to version 3.11 or later.\nFor express 4.x, update express to version 4.5 or later. ",
      "references": "",
      "access": "public",
      "severity": "test",
      "cwe": "CWE-79",
      "metadata": {
        "module_type": "Network.Library",
        "exploitability": 2,
        "affected_components": ""
      },
      "url": "https://npmjs.com/advisories/8"
    }
  ],
  "metadata": {
    "vulnerabilities": {
      "info": 0,
      "low": 6,
      "moderate": 6,
      "high": 7,
      "critical": 0
    },
    "dependencies": 27,
    "devDependencies": 0,
    "optionalDependencies": 0,
    "totalDependencies": 27
  }
}
`
