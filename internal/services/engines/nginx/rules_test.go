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

package nginx

import (
	"testing"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-NGINX-1",
			Rule: NewIncludeXFrameOptionsHeader(),
			Src:  SampleVulnerableHSNGINX1,
			Findings: []engine.Finding{
				{
					CodeSample: "",
					SourceLocation: engine.Location{
						Line:   0,
						Column: 0,
					},
				},
			},
		},
		{
			Name: "HS-NGINX-2",
			Rule: NewIncludeXContentTypeOptionsHeader(),
			Src:  SampleVulnerableHSNGINX2,
			Findings: []engine.Finding{
				{
					CodeSample: "",
					SourceLocation: engine.Location{
						Line:   0,
						Column: 0,
					},
				},
			},
		},
		{
			Name: "HS-NGINX-3",
			Rule: NewIncludeContentSecurityPolicyHeader(),
			Src:  SampleVulnerableHSNGINX3,
			Findings: []engine.Finding{
				{
					CodeSample: "",
					SourceLocation: engine.Location{
						Line:   0,
						Column: 0,
					},
				},
			},
		},
		{
			Name: "HS-NGINX-4",
			Rule: NewIncludeServerTokensOff(),
			Src:  SampleVulnerableHSNGINX4,
			Findings: []engine.Finding{
				{
					CodeSample: "",
					SourceLocation: engine.Location{
						Line:   0,
						Column: 0,
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
			Name: "HS-NGINX-1",
			Rule: NewIncludeXFrameOptionsHeader(),
			Src:  SampleSafeHSNGINX1,
		},
		{
			Name: "HS-NGINX-2",
			Rule: NewIncludeXContentTypeOptionsHeader(),
			Src:  SampleSafeHSNGINX2,
		},
		{
			Name: "HS-NGINX-3",
			Rule: NewIncludeContentSecurityPolicyHeader(),
			Src:  SampleSafeHSNGINX3,
		},
		{
			Name: "HS-NGINX-4",
			Rule: NewIncludeServerTokensOff(),
			Src:  SampleSafeHSNGINX4,
		},
	}

	testutil.TestSafeCode(t, testcases)
}
