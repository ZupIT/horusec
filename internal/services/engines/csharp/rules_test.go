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

package csharp

import (
	"testing"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-CSHARP-1",
			Rule: NewCommandInjection(),
			Src:  SampleVulnerableHSCSHARP1,
			Findings: []engine.Finding{
				{
					CodeSample: "var p = new Process();",
					SourceLocation: engine.Location{
						Line:   2,
						Column: 10,
					},
				},
			},
		},
		{
			Name: "HS-CSHARP-2",
			Rule: NewXPathInjection(),
			Src:  SampleVulnerableHSCSHARP2,
			Findings: []engine.Finding{
				{
					CodeSample: "var doc = new XmlDocument {XmlResolver = null};",
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
			Name: "HS-CSHARP-1",
			Rule: NewCommandInjection(),
			Src:  SampleSafeHSCSHARP1,
		},
		{
			Name: "HS-CSHARP-2",
			Rule: NewXPathInjection(),
			Src:  SampleSafeHSCSHARP2,
		},
	}

	testutil.TestSafeCode(t, testcases)
}
