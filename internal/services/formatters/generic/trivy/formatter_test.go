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

package trivy

import (
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

func TestTrivyParseOutput(t *testing.T) {
	t.Run("Should add 2 vulnerabilities on analysis without errors", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := new(analysis.Analysis)

		cfg := config.New()

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 2)

		for _, v := range analysis.AnalysisVulnerabilities {
			vuln := v.Vulnerability

			assert.Equal(t, tools.Trivy, vuln.SecurityTool)
			assert.Equal(t, languages.Generic, vuln.Language)
			assert.NotEmpty(t, vuln.Details, "Expected not empty details")
			assert.NotEmpty(t, vuln.Code, "Expected not empty code")
			assert.NotEmpty(t, vuln.File, "Expected not empty file name")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")

		}
	})

	t.Run("Should add error on analysis when invalid output", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid", nil)

		analysis := new(analysis.Analysis)

		cfg := config.New()

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()

		cfg := config.New()
		cfg.ToolsConfig = toolsconfig.ToolsConfig{
			tools.Trivy: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")
	})
}

const output = `
{
  "SchemaVersion": 2,
  "ArtifactName": "./",
  "ArtifactType": "filesystem",
  "Metadata": {},
  "Results": [
    {
      "Target": "go.sum",
      "Class": "lang-pkgs",
      "Type": "gomod",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2020-26160",
          "PkgName": "github.com/dgrijalva/jwt-go",
          "InstalledVersion": "3.2.0+incompatible",
          "Layer": {
            "DiffID": "sha256:f792cd543fb8711f2afbe7990dddf572b57b29f982ea03c11010972b07a28b36"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-26160",
          "Title": "jwt-go: access restriction bypass vulnerability",
          "Description": "jwt-go before 4.0.0-preview1 allows attackers to bypass intended access restrictions in situations with []string{} for m[\"aud\"] (which is allowed by the specification). Because the type assertion fails, \"\" is the value of aud. This is a security problem if the JWT token is presented to a service that lacks its own audience check.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-862"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://github.com/dgrijalva/jwt-go/pull/426",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-26160",
            "https://snyk.io/vuln/SNYK-GOLANG-GITHUBCOMDGRIJALVAJWTGO-596515"
          ],
          "PublishedDate": "2020-09-30T18:15:00Z",
          "LastModifiedDate": "2021-07-21T11:39:00Z"
        }
      ]
    }
  ]
}
`
