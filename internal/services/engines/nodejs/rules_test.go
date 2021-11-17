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

package nodejs

import (
	"testing"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-JAVASCRIPT-1",
			Rule: NewNoLogSensitiveInformationInConsole(),
			Src:  SampleVulnerableHSJAVASCRIPT1,
			Findings: []engine.Finding{
				{
					CodeSample: `console.log("user email: ", email)`,
					SourceLocation: engine.Location{
						Line:   2,
						Column: 0,
					},
				},
				{
					CodeSample: `console.debug("user password: ", pwd)`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 0,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-2",
			Rule: NewNoUseEval(),
			Src:  SampleVulnerableHSJAVASCRIPT2,
			Findings: []engine.Finding{
				{
					CodeSample: `eval(foo);`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 1,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-3",
			Rule: NewNoDisableTlsRejectUnauthorized(),
			Src:  SampleVulnerableHSJAVASCRIPT3,
			Findings: []engine.Finding{
				{
					CodeSample: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";`,
					SourceLocation: engine.Location{
						Line:   2,
						Column: 12,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-4",
			Rule: NewNoUseMD5Hashing(),
			Src:  SampleVulnerableHSJAVASCRIPT4,
			Findings: []engine.Finding{
				{
					CodeSample: `const hash = crypto.createHash('md5')`,
					SourceLocation: engine.Location{
						Line:   2,
						Column: 20,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-5",
			Rule: NewNoUseSHA1Hashing(),
			Src:  SampleVulnerableHSJAVASCRIPT5,
			Findings: []engine.Finding{
				{
					CodeSample: `const hash = crypto.createHash('sha1')`,
					SourceLocation: engine.Location{
						Line:   2,
						Column: 20,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-6",
			Rule: NewNoUseWeakRandom(),
			Src:  SampleVulnerableHSJAVASCRIPT6,
			Findings: []engine.Finding{
				{
					CodeSample: `return Math.random();`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 8,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-7",
			Rule: NewNoReadFileUsingDataFromRequest(),
			Src:  SampleVulnerableHSJAVASCRIPT7,
			Findings: []engine.Finding{
				{
					CodeSample: `return fs.readFileSync(req.body, 'utf8')`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 10,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-8",
			Rule: NewNoCreateReadStreamUsingDataFromRequest(),
			Src:  SampleVulnerableHSJAVASCRIPT8,
			Findings: []engine.Finding{
				{
					CodeSample: `return fs.createReadStream(req.body)`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 10,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-9",
			Rule: NewSQLInjectionUsingParams(),
			Src:  SampleVulnerableHSJAVASCRIPT9,
			Findings: []engine.Finding{
				{
					CodeSample: `Model.find({ where: { foo: req.body}});`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 6,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-10",
			Rule: NewXMLParsersShouldNotBeVulnerableToXXEAttacks(),
			Src:  SampleVulnerableHSJAVASCRIPT10,
			Findings: []engine.Finding{
				{
					CodeSample: `var xmlDoc = libxml.parseXmlString(xml, {});`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 19,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-11",
			Rule: NewOriginsNotVerified(),
			Src:  SampleVulnerableHSJAVASCRIPT11,
			Findings: []engine.Finding{
				{
					CodeSample: `popup.postMessage("message", "https://foo.bar", "*");`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 6,
					},
				},
				{
					CodeSample: `window.addEventListener("message", (event) => {});`,
					SourceLocation: engine.Location{
						Line:   8,
						Column: 7,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-12",
			Rule: NewWeakSSLTLSProtocolsShouldNotBeUsed(),
			Src:  SampleVulnerableHSJAVASCRIPT12,
			Findings: []engine.Finding{
				{
					CodeSample: `secureProtocol: 'TLSv1_method'`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 19,
					},
				},
				{
					CodeSample: `secureProtocol: 'TLSv1.1'`,
					SourceLocation: engine.Location{
						Line:   10,
						Column: 19,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-13",
			Rule: NewWebSQLDatabasesShouldNotBeUsed(),
			Src:  SampleVulnerableHSJAVASCRIPT13,
			Findings: []engine.Finding{
				{
					CodeSample: `const db = window.openDatabase();`,
					SourceLocation: engine.Location{
						Line:   2,
						Column: 11,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-14",
			Rule: NewLocalStorageShouldNotBeUsed(),
			Src:  SampleVulnerableHSJAVASCRIPT14,
			Findings: []engine.Finding{
				{
					CodeSample: `localStorage.setItem("foo", "bar");`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 1,
					},
				},
				{
					CodeSample: `sessionStorage.setItem("foo", "bar");`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 1,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-15",
			Rule: NewDebuggerStatementsShouldNotBeUsed(),
			Src:  SampleVulnerableHSJAVASCRIPT15,
			Findings: []engine.Finding{
				{
					CodeSample: `debugger;`,
					SourceLocation: engine.Location{
						Line:   2,
						Column: 1,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-16",
			Rule: NewAlertStatementsShouldNotBeUsed(),
			Src:  SampleVulnerableHSJAVASCRIPT16,
			Findings: []engine.Finding{
				{
					CodeSample: `alert("testing");`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 1,
					},
				},
				{
					CodeSample: `confirm("testing");`,
					SourceLocation: engine.Location{
						Line:   7,
						Column: 1,
					},
				},
				{
					CodeSample: `prompt("testing");`,
					SourceLocation: engine.Location{
						Line:   11,
						Column: 1,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-17",
			Rule: NewStaticallyServingHiddenFilesIsSecuritySensitive(),
			Src:  SampleVulnerableHSJAVASCRIPT17,
			Findings: []engine.Finding{
				{
					CodeSample: `dotfiles : 'allow'`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 2,
					},
				},
			},
		},
		{
			Name: "HS-JAVASCRIPT-18",
			Rule: NewUsingIntrusivePermissionsWithGeolocation(),
			Src:  SampleVulnerableHSJAVASCRIPT18,
			Findings: []engine.Finding{
				{
					CodeSample: `navigator.geolocation.getCurrentPosition(success, error, {});`,
					SourceLocation: engine.Location{
						Line:   10,
						Column: 10,
					},
				},
			},
		},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-JAVASCRIPT-2",
			Rule: NewNoUseEval(),
			Src:  SampleSafeHSJAVASCRIPT2,
		},
		{
			Name: "HS-JAVASCRIPT-9",
			Rule: NewSQLInjectionUsingParams(),
			Src:  SampleSafeHSJAVASCRIPT9,
		},
		{
			Name: "HS-JAVASCRIPT-10",
			Rule: NewXMLParsersShouldNotBeVulnerableToXXEAttacks(),
			Src:  SampleSafeHSJAVASCRIPT10,
		},
		{
			Name: "HS-JAVASCRIPT-11",
			Rule: NewOriginsNotVerified(),
			Src:  SampleSafeHSJAVASCRIPT11,
		},
		{
			Name: "HS-JAVASCRIPT-12",
			Rule: NewWeakSSLTLSProtocolsShouldNotBeUsed(),
			Src:  SampleSafeHSJAVASCRIPT12,
		},
		{
			Name: "HS-JAVASCRIPT-17",
			Rule: NewStaticallyServingHiddenFilesIsSecuritySensitive(),
			Src:  SampleSafeHSJAVASCRIPT17,
		},
	}

	testutil.TestSafeCode(t, testcases)
}
