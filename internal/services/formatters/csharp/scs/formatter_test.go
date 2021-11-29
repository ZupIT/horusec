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

package scs_test

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
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/scs"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestParseOutput(t *testing.T) {
	t.Run("should add 4 vulnerabilities on analysis with no errors", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		cfg := newTestConfig(t, analysis)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := scs.NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 4)

		for _, v := range analysis.AnalysisVulnerabilities {
			vuln := v.Vulnerability

			assert.Equal(t, tools.SecurityCodeScan, vuln.SecurityTool)
			assert.Equal(t, languages.CSharp, vuln.Language)
			assert.NotEmpty(t, vuln.Details, "Expected not empty details")
			assert.NotEmpty(t, vuln.Code, "Expected not empty code")
			assert.Equal(
				t,
				filepath.Join("NetCoreVulnerabilities", "Vulnerabilities.cs"),
				vuln.File,
				"Expected equals file name",
			)
			assert.NotEmpty(t, vuln.Line, "Expected not empty line")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")

		}
	})

	t.Run("should add error on analysis when parse invalid output", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")

		cfg := newTestConfig(t, analysis)

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := scs.NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should add build error on analysis", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(scs.BuildFailedOutput, nil)

		cfg := newTestConfig(t, analysis)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := scs.NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should add error of not found solution file on analysis", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(scs.SolutionFileNotFound, nil)

		cfg := newTestConfig(t, analysis)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := scs.NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should add error of executing container on analysis", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		cfg := newTestConfig(t, analysis)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := scs.NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should not execute tool because it's ignored", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()

		cfg := config.New()
		cfg.ToolsConfig = toolsconfig.ToolsConfig{
			tools.SecurityCodeScan: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := scs.NewFormatter(service)

		formatter.StartAnalysis("")
	})
}

func newTestConfig(t *testing.T, analysiss *analysis.Analysis) *config.Config {
	cfg := config.New()
	cfg.ProjectPath = testutil.CreateHorusecAnalysisDirectory(t, analysiss, testutil.CsharpExample1)
	return cfg
}

const output = `
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "version": "2.1.0",
  "runs": [
    {
      "results": [
        {
          "ruleId": "SCS0006",
          "ruleIndex": 0,
          "level": "warning",
          "message": {
            "text": "Weak hashing function."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "file:///src/NetCoreVulnerabilities/Vulnerabilities.cs"
                },
                "region": {
                  "startLine": 22,
                  "startColumn": 32,
                  "endLine": 22,
                  "endColumn": 63
                }
              }
            }
          ],
          "properties": {
            "warningLevel": 1
          }
        },
        {
          "ruleId": "SCS0006",
          "ruleIndex": 0,
          "level": "warning",
          "message": {
            "text": "Weak hashing function."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "file:///src/NetCoreVulnerabilities/Vulnerabilities.cs"
                },
                "region": {
                  "startLine": 15,
                  "startColumn": 32,
                  "endLine": 15,
                  "endColumn": 63
                }
              }
            }
          ],
          "properties": {
            "warningLevel": 1
          }
        },
        {
          "ruleId": "SCS0005",
          "ruleIndex": 1,
          "level": "warning",
          "message": {
            "text": "Weak random number generator."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "file:///src/NetCoreVulnerabilities/Vulnerabilities.cs"
                },
                "region": {
                  "startLine": 37,
                  "startColumn": 13,
                  "endLine": 37,
                  "endColumn": 26
                }
              }
            }
          ],
          "properties": {
            "warningLevel": 1
          }
        },
        {
          "ruleId": "",
          "ruleIndex": 2,
          "level": "warning",
          "message": {
            "text": "Hardcoded value in 'string password'."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "file:///src/NetCoreVulnerabilities/Vulnerabilities.cs"
                },
                "region": {
                  "startLine": 28,
                  "startColumn": 34,
                  "endLine": 28,
                  "endColumn": 88
                }
              }
            }
          ],
          "relatedLocations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "file:///src/NetCoreVulnerabilities/Vulnerabilities.cs"
                },
                "region": {
                  "startLine": 28,
                  "startColumn": 34,
                  "endLine": 28,
                  "endColumn": 88
                }
              }
            }
          ],
          "properties": {
            "warningLevel": 1
          }
        }
      ],
      "tool": {
        "driver": {
          "name": "Security Code Scan",
          "version": "5.1.1.0",
          "dottedQuadFileVersion": "5.1.1.0",
          "semanticVersion": "5.1.1",
          "language": "",
          "rules": [
            {
              "id": "SCS0006",
              "shortDescription": {
                "text": "Weak hashing function."
              },
              "fullDescription": {
                "text": "SHA1 is no longer considered as a strong hashing algorithm."
              },
              "helpUri": "https://security-code-scan.github.io/#SCS0006",
              "properties": {
                "category": "Security"
              }
            },
            {
              "id": "SCS0005",
              "shortDescription": {
                "text": "Weak random number generator."
              },
              "fullDescription": {
                "text": "It is possible to predict the next numbers of a pseudo random generator. Use a cryptographically strong generator for security sensitive purposes."
              },
              "helpUri": "https://security-code-scan.github.io/#SCS0005",
              "properties": {
                "category": "Security"
              }
            },
            {
              "id": "SCS0015",
              "shortDescription": {
                "text": "Hardcoded value in '{0}'."
              },
              "fullDescription": {
                "text": "The secret value to this API appears to be hardcoded. Consider moving the value to externalized configuration to avoid leakage of secret information."
              },
              "helpUri": "https://security-code-scan.github.io/#SCS0015",
              "properties": {
                "category": "Security"
              }
            }
          ]
        }
      },
      "columnKind": "utf16CodeUnits"
    }
  ]
}
`
