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

package printresults

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	vulnerabilityenum "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/internal/enums/outputtype"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/utils/mock"
	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec/config"
)

type validateFn func(t *testing.T, tt testcase)

type testcase struct {
	name            string
	cfg             config.Config
	analysis        analysis.Analysis
	vulnerabilities int
	outputs         []string
	err             bool
	validateFn      validateFn
}

func TestStartPrintResultsMock(t *testing.T) {
	t.Run("Should return correctly mock", func(t *testing.T) {
		m := &Mock{}
		m.On("StartPrintResults").Return(0, nil)

		totalVulns, err := m.Print()
		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})
}

func TestPrintResultsStartPrintResults(t *testing.T) {
	testcases := []testcase{
		{
			name: "Should not return error using default output type text",
			cfg:  config.Config{},
			analysis: entitiesAnalysis.Analysis{
				AnalysisVulnerabilities: []entitiesAnalysis.AnalysisVulnerabilities{},
			},
		},
		{
			name: "Should not return error using output type json",
			cfg: config.Config{
				StartOptions: config.StartOptions{
					JSONOutputFilePath: filepath.Join(t.TempDir(), "json-output.json"),
					PrintOutputType:    outputtype.JSON,
				},
			},
			analysis: entitiesAnalysis.Analysis{
				AnalysisVulnerabilities: []entitiesAnalysis.AnalysisVulnerabilities{
					{
						VulnerabilityID: uuid.MustParse("57bf7b03-b504-42ed-a026-ea89c81b7f4a"),
						AnalysisID:      uuid.MustParse("16c70059-aa76-4b00-87d6-ad9941f8603e"),
						Vulnerability: vulnerability.Vulnerability{

							VulnerabilityID: uuid.MustParse("54a7a2a9-d68e-4139-ba53-6bff3bc84863"),
							Line:            "1",
							Column:          "0",
							Confidence:      confidence.High,
							File:            "cert.pem",
							Code:            "-----BEGIN CERTIFICATE-----",
							Details:         "Found SSH and/or x.509 Cerficates GoSec",
							SecurityTool:    tools.GoSec,
							Language:        languages.Go,
							Severity:        severities.Low,
							Type:            vulnerabilityenum.Vulnerability,
						},
					},
				},
			},
			vulnerabilities: 1,
			validateFn: func(t *testing.T, tt testcase) {
				assert.FileExists(t, tt.cfg.JSONOutputFilePath)

				json := readFile(t, tt.cfg.JSONOutputFilePath)
				assert.JSONEq(t, expectedJsonResult, string(json))
			},
		},
		{
			name: "Should not return error using output type sonarqube",
			cfg: config.Config{
				StartOptions: config.StartOptions{
					PrintOutputType:    outputtype.SonarQube,
					JSONOutputFilePath: filepath.Join(t.TempDir(), "sonar-output.json"),
				},
			},
			analysis: *mock.CreateAnalysisMock(),
			outputs:  []string{messages.MsgInfoStartGenerateSonarQubeFile},
			validateFn: func(t *testing.T, tt testcase) {
				assert.FileExists(t, tt.cfg.JSONOutputFilePath)

				json := readFile(t, tt.cfg.JSONOutputFilePath)
				assert.JSONEq(t, expectedSonarqubeJsonResult, string(json))
			},
			vulnerabilities: 11,
		},
		{
			name: "Should return not errors because exists error in analysis",
			cfg:  config.Config{},
			analysis: entitiesAnalysis.Analysis{
				AnalysisVulnerabilities: []entitiesAnalysis.AnalysisVulnerabilities{},
				Errors:                  "Exists an error when read analysis",
			},
		},
		{
			name: "Should return error when using json output type without output file path",
			cfg: config.Config{
				StartOptions: config.StartOptions{
					PrintOutputType: outputtype.JSON,
				},
			},
			analysis: *mock.CreateAnalysisMock(),
			err:      true,
			outputs:  []string{messages.MsgErrorGenerateJSONFile},
		},
		{
			name: "Should return 11 vulnerabilities with timeout occurs",
			cfg: config.Config{
				GlobalOptions: config.GlobalOptions{
					IsTimeout: true,
				},
			},
			analysis:        *mock.CreateAnalysisMock(),
			vulnerabilities: 11,
			outputs:         []string{messages.MsgWarnTimeoutOccurs},
		},
		{
			name:            "Should print 11 vulnerabilities",
			cfg:             config.Config{},
			analysis:        *mock.CreateAnalysisMock(),
			vulnerabilities: 11,
		},
		{
			name: "Should print 11 vulnerabilities with commit authors",
			cfg: config.Config{
				StartOptions: config.StartOptions{
					EnableCommitAuthor: true,
				},
			},
			analysis:        *mock.CreateAnalysisMock(),
			vulnerabilities: 11,
			outputs: []string{
				"Commit Author", "Commit Date", "Commit Email", "Commit CommitHash", "Commit Message",
			},
		},
		{
			name: "Should not return errors when configured to ignore vulnerabilities with severity LOW and MEDIUM",
			cfg: config.Config{
				StartOptions: config.StartOptions{
					SeveritiesToIgnore: []string{"MEDIUM", "LOW"},
				},
			},
			analysis:        *mock.CreateAnalysisMock(),
			vulnerabilities: 3,
		},
		{
			name: "Should save output to file when using json output file path and text format",
			cfg: config.Config{
				StartOptions: config.StartOptions{
					PrintOutputType:    outputtype.Text,
					JSONOutputFilePath: filepath.Join(t.TempDir(), "output"),
				},
			},
			analysis:        *mock.CreateAnalysisMock(),
			vulnerabilities: 11,
			validateFn: func(t *testing.T, tt testcase) {
				assert.FileExists(t, tt.cfg.JSONOutputFilePath, "output")

				output := string(readFile(t, tt.cfg.JSONOutputFilePath))

				for _, line := range strings.Split(expectedTextResult, "\n") {
					assert.Contains(t, output, line)
				}
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			pr, output := newPrintResultsTest(&tt.analysis, &tt.cfg)
			totalVulns, err := pr.Print()

			if tt.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.vulnerabilities, totalVulns)

			s := output.String()
			for _, output := range tt.outputs {
				assert.Contains(t, s, output)
			}

			if tt.validateFn != nil {
				tt.validateFn(t, tt)
			}
		})
	}
}

// newPrintResultsTest creates a new PrintResults using the bytes.Buffer
// from return as a print results writer and logger output.
func newPrintResultsTest(entity *analysis.Analysis, cfg *config.Config) (*PrintResults, *bytes.Buffer) {
	output := bytes.NewBufferString("")
	pr := NewPrintResults(entity, cfg)
	pr.writer = output

	logger.LogSetOutput(output)

	return pr, output
}

func readFile(t *testing.T, path string) []byte {
	b, err := os.ReadFile(path)
	require.Nil(t, err, "Expected nil error to read file %s: %v", path, err)
	return b
}

const (
	// expectedJsonResult is the expected json result saved on file.
	expectedJsonResult = `
{
  "version": "",
  "id": "00000000-0000-0000-0000-000000000000",
  "repositoryID": "00000000-0000-0000-0000-000000000000",
  "repositoryName": "",
  "workspaceID": "00000000-0000-0000-0000-000000000000",
  "workspaceName": "",
  "status": "",
  "errors": "",
  "createdAt": "0001-01-01T00:00:00Z",
  "finishedAt": "0001-01-01T00:00:00Z",
  "analysisVulnerabilities": [
    {
      "vulnerabilityID": "57bf7b03-b504-42ed-a026-ea89c81b7f4a",
      "analysisID": "16c70059-aa76-4b00-87d6-ad9941f8603e",
      "createdAt": "0001-01-01T00:00:00Z",
      "vulnerabilities": {
        "vulnerabilityID": "54a7a2a9-d68e-4139-ba53-6bff3bc84863",
        "line": "1",
        "column": "0",
        "confidence": "HIGH",
        "file": "cert.pem",
        "code": "-----BEGIN CERTIFICATE-----",
        "details": "Found SSH and/or x.509 Cerficates GoSec",
        "securityTool": "GoSec",
        "language": "Go",
        "severity": "LOW",
        "type": "Vulnerability",
        "commitAuthor": "",
        "commitEmail": "",
        "commitHash": "",
        "commitMessage": "",
        "commitDate": "",
        "vulnHash": ""
      }
    }
  ]
}
`

	// expectedTextResult is the expected text result saved on file.
	expectedTextResult = `
==================================================================================

Language: Go
Severity: LOW
Line: 1
Column: 0
SecurityTool: GoSec
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates GoSec
Type: Vulnerability
ReferenceHash: e85cdcb9de69717b2c63f2367ae75c3cc0162acefc6714986eab55e6a52b0bab

==================================================================================

Language: C#
Severity: MEDIUM
Line: 1
Column: 0
SecurityTool: SecurityCodeScan
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates SecurityCodeScan
Type: Vulnerability
ReferenceHash: 3889442bd5280ea3b7bd89408d478f3d7fcfb6b78bc1e2e53e726344fc47f9bf

==================================================================================

Language: Ruby
Severity: HIGH
Line: 1
Column: 0
SecurityTool: Brakeman
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates Brakeman
Type: Vulnerability
ReferenceHash: fc9fd74b92f16d962a4758fa2b05bca09e0912e49c01d2dc5faf11a798b62480

==================================================================================

Language: JavaScript
Severity: LOW
Line: 1
Column: 0
SecurityTool: NpmAudit
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates NpmAudit
Type: Vulnerability
ReferenceHash: a4774674dcff66efdafe4c58df5e2cc72f768330e79187f79e93838dc7875a9e

==================================================================================

Language: JavaScript
Severity: LOW
Line: 1
Column: 0
SecurityTool: YarnAudit
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates YarnAudit
Type: Vulnerability
ReferenceHash: 2821233bffb27450b1e24453c491a36834db50417fc70eb9d7d0af057a455126

==================================================================================

Language: Python
Severity: LOW
Line: 1
Column: 0
SecurityTool: Bandit
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates Bandit
Type: Vulnerability
ReferenceHash: dcff5a09607c641c7b127bf53d6efc38533f7fb601f0b00862e0d7738b25aa5d

==================================================================================

Language: Python
Severity: LOW
Line: 1
Column: 0
SecurityTool: Safety
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates Safety
Type: Vulnerability
ReferenceHash: 1322569065b57231b2c21981a74f61710060ca967aa824c1634a791241bc5b86

==================================================================================

Language: Leaks
Severity: HIGH
Line: 1
Column: 0
SecurityTool: HorusecEngine
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates HorusecLeaks
Type: Vulnerability
ReferenceHash: 5829ce1578d6b902c2f545181f4b8e836f29da72702fa53c0bd2caad77e869dd

==================================================================================

Language: Leaks
Severity: HIGH
Line: 1
Column: 0
SecurityTool: GitLeaks
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates GitLeaks
Type: Vulnerability
ReferenceHash: 1cb3d3e481f1b28514f06631d31a10bab589509e3fac4354fbf210e980535f72

==================================================================================

Language: Java
Severity: LOW
Line: 1
Column: 0
SecurityTool: HorusecEngine
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates HorusecJava
Type: Vulnerability
ReferenceHash: b7684b5d431ba356f65e8dbe3c62ee24cd97412094b5ae205c99670ed54f883d

==================================================================================

Language: Kotlin
Severity: LOW
Line: 1
Column: 0
SecurityTool: HorusecEngine
Confidence: HIGH
File: cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Found SSH and/or x.509 Cerficates HorusecKotlin
Type: Vulnerability
ReferenceHash: 9824269893d4df5e66a4fe7f53a715117bb722910228152b04831b6d2ad19a5b

==================================================================================

In this analysis, a total of 11 possible vulnerabilities were found and we classified them into:
Total of False Positive HIGH is: 3
Total of False Positive MEDIUM is: 1
Total of False Positive LOW is: 7
Total of Corrected HIGH is: 3
Total of Corrected MEDIUM is: 1
Total of Corrected LOW is: 7
Total of Vulnerability HIGH is: 3
Total of Vulnerability MEDIUM is: 1
Total of Vulnerability LOW is: 7
Total of Risk Accepted HIGH is: 3
Total of Risk Accepted MEDIUM is: 1
Total of Risk Accepted LOW is: 7

`

	// expectedSonarqubeJsonResult is the expected json result
	// using Sonarqube format saved on file.
	expectedSonarqubeJsonResult = `
{
  "issues": [
    {
      "type": "VULNERABILITY",
      "ruleId": "GoSec",
      "engineId": "horusec",
      "severity": "MINOR",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates GoSec",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    },
    {
      "type": "VULNERABILITY",
      "ruleId": "SecurityCodeScan",
      "engineId": "horusec",
      "severity": "MAJOR",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates SecurityCodeScan",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    },
    {
      "type": "VULNERABILITY",
      "ruleId": "Brakeman",
      "engineId": "horusec",
      "severity": "CRITICAL",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates Brakeman",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    },
    {
      "type": "VULNERABILITY",
      "ruleId": "NpmAudit",
      "engineId": "horusec",
      "severity": "MINOR",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates NpmAudit",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    },
    {
      "type": "VULNERABILITY",
      "ruleId": "YarnAudit",
      "engineId": "horusec",
      "severity": "MINOR",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates YarnAudit",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    },
    {
      "type": "VULNERABILITY",
      "ruleId": "Bandit",
      "engineId": "horusec",
      "severity": "MINOR",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates Bandit",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    },
    {
      "type": "VULNERABILITY",
      "ruleId": "Safety",
      "engineId": "horusec",
      "severity": "MINOR",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates Safety",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    },
    {
      "type": "VULNERABILITY",
      "ruleId": "HorusecEngine",
      "engineId": "horusec",
      "severity": "CRITICAL",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates HorusecLeaks",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    },
    {
      "type": "VULNERABILITY",
      "ruleId": "GitLeaks",
      "engineId": "horusec",
      "severity": "CRITICAL",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates GitLeaks",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    },
    {
      "type": "VULNERABILITY",
      "ruleId": "HorusecEngine",
      "engineId": "horusec",
      "severity": "MINOR",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates HorusecJava",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    },
    {
      "type": "VULNERABILITY",
      "ruleId": "HorusecEngine",
      "engineId": "horusec",
      "severity": "MINOR",
      "effortMinutes": 0,
      "primaryLocation": {
        "message": "Found SSH and/or x.509 Cerficates HorusecKotlin",
        "filePath": "cert.pem",
        "textRange": {
          "startLine": 1,
          "startColumn": 1
        }
      }
    }
  ]
}
`
)
