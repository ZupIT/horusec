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

package javascript

import (
	"fmt"
	"path/filepath"
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	tempDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-JAVASCRIPT-1",
			Rule:     NewNoLogSensitiveInformationInConsole(),
			Src:      SampleVulnerableHSJAVASCRIPT1,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-1", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `console.log("user email: ", email)`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-1", ".test")),
						Line:     2,
						Column:   0,
					},
				},
				{
					CodeSample: `console.debug("user password: ", pwd)`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-1", ".test")),
						Line:     3,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-2",
			Rule:     NewNoUseEval(),
			Src:      SampleVulnerableHSJAVASCRIPT2,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-2", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `eval(foo);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-2", ".test")),
						Line:     3,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-3",
			Rule:     NewNoDisableTlsRejectUnauthorized(),
			Src:      SampleVulnerableHSJAVASCRIPT3,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-3", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-3", ".test")),
						Line:     2,
						Column:   12,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-4",
			Rule:     NewNoUseMD5Hashing(),
			Src:      SampleVulnerableHSJAVASCRIPT4,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-4", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `const hash = crypto.createHash('md5')`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-4", ".test")),
						Line:     2,
						Column:   20,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-5",
			Rule:     NewNoUseSHA1Hashing(),
			Src:      SampleVulnerableHSJAVASCRIPT5,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-5", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `const hash = crypto.createHash('sha1')`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-5", ".test")),
						Line:     2,
						Column:   20,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-6",
			Rule:     NewNoUseWeakRandom(),
			Src:      SampleVulnerableHSJAVASCRIPT6,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-6", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `return Math.random();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-6", ".test")),
						Line:     3,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-7",
			Rule:     NewNoReadFileUsingDataFromRequest(),
			Src:      SampleVulnerableHSJAVASCRIPT7,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-7", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `return fs.readFileSync(req.body, 'utf8')`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-7", ".test")),
						Line:     3,
						Column:   10,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-8",
			Rule:     NewNoCreateReadStreamUsingDataFromRequest(),
			Src:      SampleVulnerableHSJAVASCRIPT8,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-8", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `return fs.createReadStream(req.body)`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-8", ".test")),
						Line:     3,
						Column:   10,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-9",
			Rule:     NewSQLInjectionUsingParams(),
			Src:      SampleVulnerableHSJAVASCRIPT9,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-9", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `Model.find({ where: { foo: req.body}});`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-9", ".test")),
						Line:     3,
						Column:   6,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-10",
			Rule:     NewXMLParsersShouldNotBeVulnerableToXXEAttacks(),
			Src:      SampleVulnerableHSJAVASCRIPT10,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-10", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `var xmlDoc = libxml.parseXmlString(xml, {});`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-10", ".test")),
						Line:     4,
						Column:   19,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-11",
			Rule:     NewOriginsNotVerified(),
			Src:      SampleVulnerableHSJAVASCRIPT11,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-11", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `popup.postMessage("message", "https://foo.bar", "*");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-11", ".test")),
						Line:     4,
						Column:   6,
					},
				},
				{
					CodeSample: `window.addEventListener("message", (event) => {});`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-11", ".test")),
						Line:     8,
						Column:   7,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-12",
			Rule:     NewWeakSSLTLSProtocolsShouldNotBeUsed(),
			Src:      SampleVulnerableHSJAVASCRIPT12,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-12", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `secureProtocol: 'TLSv1_method'`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-12", ".test")),
						Line:     4,
						Column:   19,
					},
				},
				{
					CodeSample: `secureProtocol: 'TLSv1.1'`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-12", ".test")),
						Line:     10,
						Column:   19,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-13",
			Rule:     NewWebSQLDatabasesShouldNotBeUsed(),
			Src:      SampleVulnerableHSJAVASCRIPT13,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-13", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `const db = window.openDatabase();`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-13", ".test")),
						Line:     2,
						Column:   11,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-14",
			Rule:     NewLocalStorageShouldNotBeUsed(),
			Src:      SampleVulnerableHSJAVASCRIPT14,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-14", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `localStorage.setItem("foo", "bar");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-14", ".test")),
						Line:     3,
						Column:   1,
					},
				},
				{
					CodeSample: `sessionStorage.setItem("foo", "bar");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-14", ".test")),
						Line:     7,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-15",
			Rule:     NewDebuggerStatementsShouldNotBeUsed(),
			Src:      SampleVulnerableHSJAVASCRIPT15,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-15", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `debugger;`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-15", ".test")),
						Line:     2,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-16",
			Rule:     NewAlertStatementsShouldNotBeUsed(),
			Src:      SampleVulnerableHSJAVASCRIPT16,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-16", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `alert("testing");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-16", ".test")),
						Line:     3,
						Column:   1,
					},
				},
				{
					CodeSample: `confirm("testing");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-16", ".test")),
						Line:     7,
						Column:   1,
					},
				},
				{
					CodeSample: `prompt("testing");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-16", ".test")),
						Line:     11,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-17",
			Rule:     NewStaticallyServingHiddenFilesIsSecuritySensitive(),
			Src:      SampleVulnerableHSJAVASCRIPT17,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-17", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `dotfiles : 'allow'`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-17", ".test")),
						Line:     3,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-18",
			Rule:     NewUsingIntrusivePermissionsWithGeolocation(),
			Src:      SampleVulnerableHSJAVASCRIPT18,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-18", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `navigator.geolocation.getCurrentPosition(success, error, {});`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-18", ".test")),
						Line:     10,
						Column:   10,
					},
				},
			},
		},
		{
			Name:     "HS-JAVASCRIPT-19",
			Rule:     NewHavingAPermissiveCrossOriginResourceSharingPolicy(),
			Src:      SampleVulnerableHSJAVASCRIPT19,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-19", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: `res.header("Access-Control-Allow-Origin", "*");`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-19", ".test")),
						Line:     7,
						Column:   14,
					},
				},
				{
					CodeSample: `app.get('/products/:id', cors(), function (req, res, next) {`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-19", ".test")),
						Line:     6,
						Column:   25,
					},
				},
				{
					CodeSample: `origin: '*',`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-19", ".test")),
						Line:     3,
						Column:   2,
					},
				},
			},
		},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	tempDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-JAVASCRIPT-2",
			Rule:     NewNoUseEval(),
			Src:      SampleSafeHSJAVASCRIPT2,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-1", ".test")),
		},
		{
			Name:     "HS-JAVASCRIPT-9",
			Rule:     NewSQLInjectionUsingParams(),
			Src:      SampleSafeHSJAVASCRIPT9,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-9", ".test")),
		},
		{
			Name:     "HS-JAVASCRIPT-10",
			Rule:     NewXMLParsersShouldNotBeVulnerableToXXEAttacks(),
			Src:      SampleSafeHSJAVASCRIPT10,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-10", ".test")),
		},
		{
			Name:     "HS-JAVASCRIPT-11",
			Rule:     NewOriginsNotVerified(),
			Src:      SampleSafeHSJAVASCRIPT11,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-11", ".test")),
		},
		{
			Name:     "HS-JAVASCRIPT-12",
			Rule:     NewWeakSSLTLSProtocolsShouldNotBeUsed(),
			Src:      SampleSafeHSJAVASCRIPT12,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-12", ".test")),
		},
		{
			Name:     "HS-JAVASCRIPT-17",
			Rule:     NewStaticallyServingHiddenFilesIsSecuritySensitive(),
			Src:      SampleSafeHSJAVASCRIPT17,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-17", ".test")),
		},
		{
			Name:     "HS-JAVASCRIPT-19",
			Rule:     NewHavingAPermissiveCrossOriginResourceSharingPolicy(),
			Src:      SampleSafeHSJAVASCRIPT19,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-19", ".test")),
		},
	}

	testutil.TestSafeCode(t, testcases)
}
