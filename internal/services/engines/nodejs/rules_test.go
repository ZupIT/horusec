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
			Src:  SampleVulnerableJavaScriptLogSensitiveInformation,
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
			Src:  SampleVulnerableJavaScriptUseEval,
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
			Src:  SampleVulnerableJavaScriptDisableTlsRejectUnauthorized,
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
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-JAVASCRIPT-2",
			Rule: NewNoUseEval(),
			Src:  SampleSafeJavaScriptUseEval,
		},
	}

	testutil.TestSafeCode(t, testcases)
}
