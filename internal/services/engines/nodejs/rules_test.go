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
					CodeSample: `eval("bash -c" + req.body);`,
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
	}

	testutil.TestSafeCode(t, testcases)
}
