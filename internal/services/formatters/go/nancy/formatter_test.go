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

package nancy

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
	t.Run("should success parse output to analysis", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		cfg := config.New()
		cfg.ProjectPath = testutil.CreateHorusecAnalysisDirectory(t, analysis, testutil.GoExample1)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 2)

		for _, vuln := range analysis.AnalysisVulnerabilities {
			assert.Equal(t, languages.Go, vuln.Vulnerability.Language, "Expected Go as vulnerability language")
			assert.Equal(t, tools.Nancy, vuln.Vulnerability.SecurityTool, "Expected nancy as security tool")
			assert.NotEmpty(t, vuln.Vulnerability.Severity, "Expected not empty vulnerability severity")
			assert.NotEmpty(t, vuln.Vulnerability.Details, "Expected not empty vulnerability details")
			assert.Equal(t, confidence.High, vuln.Vulnerability.Confidence, "Expected high as vulnerability confidence")
			assert.NotEmpty(t, vuln.Vulnerability.Code, "Expected not empty vulnerability code")
			assert.NotEmpty(t, vuln.Vulnerability.Line, "Expected not empty vulnerability line")
			assert.Equal(
				t,
				filepath.Join(cfg.ProjectPath, "go.mod"),
				vuln.Vulnerability.File,
				"Expected equals vulnerability file",
			)
		}
	})

	t.Run("should success parse output empty to analysis", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		cfg := config.New()

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})

	t.Run("should add error on analysis when parsing invalid output", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		cfg := config.New()

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid output", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should add error on analysis when something went wrong executing container", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		cfg := config.New()

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)

		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should not execute tool because it's ignored", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()

		cfg := config.New()
		cfg.ToolsConfig = toolsconfig.ToolsConfig{
			tools.Nancy: toolsconfig.Config{
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
  "Vulnerable": [
    {
      "Coordinates": "pkg:golang/github.com/gorilla/websocket@1.4.0",
      "Reference": "https://ossindex.sonatype.org/component/pkg:golang/github.com/gorilla/websocket@1.4.0?utm_source=nancy-client\\u0026utm_medium=integration\\u0026utm_content=0.0.0-dev",
      "Vulnerabilities": [
        {
          "ID": "5f259e63-3efb-4c47-b593-d175dca716b0",
          "Title": "CWE-190: Integer Overflow or Wraparound",
          "Description": "The software performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value. This can introduce other weaknesses when the calculation is used for resource management or execution control.",
          "CvssScore": "7.5",
          "CvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          "Cve": "",
          "Reference": "https://ossindex.sonatype.org/vulnerability/5f259e63-3efb-4c47-b593-d175dca716b0?component-type=golang\\u0026component-name=github.com%2Fgorilla%2Fwebsocket\\u0026utm_source=nancy-client\\u0026utm_medium=integration\\u0026utm_content=0.0.0-dev",
          "Excluded": false
        }
      ],
      "InvalidSemVer": false
    },
    {
      "Coordinates": "pkg:golang/golang.org/x/crypto@0.0.0-20190308221718-c2843e01d9a2",
      "Reference": "https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/crypto@0.0.0-20190308221718-c2843e01d9a2?utm_source=nancy-client\\u0026utm_medium=integration\\u0026utm_content=0.0.0-dev",
      "Vulnerabilities": [
        {
          "ID": "5121f5ff-9831-44a6-af2e-24f7301d1df7",
          "Title": "[CVE-2019-11840]  Use of Insufficiently Random Values",
          "Description": "An issue was discovered in supplementary Go cryptography libraries, aka golang-googlecode-go-crypto, before 2019-03-20. A flaw was found in the amd64 implementation of golang.org/x/crypto/salsa20 and golang.org/x/crypto/salsa20/salsa. If more than 256 GiB of keystream is generated, or if the counter otherwise grows greater than 32 bits, the amd64 implementation will first generate incorrect output, and then cycle back to previously generated keystream. Repeated keystream bytes can lead to loss of confidentiality in encryption applications, or to predictability in CSPRNG applications.",
          "CvssScore": "5.9",
          "CvssVector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
          "Cve": "CVE-2019-11840",
          "Reference": "https://ossindex.sonatype.org/vulnerability/5121f5ff-9831-44a6-af2e-24f7301d1df7?component-type=golang\\u0026component-name=golang.org%2Fx%2Fcrypto\\u0026utm_source=nancy-client\\u0026utm_medium=integration\\u0026utm_content=0.0.0-dev",
          "Excluded": false
        }
      ],
      "InvalidSemVer": false
    }
  ]
}
`
