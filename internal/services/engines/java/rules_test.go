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

package java

import (
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-JAVA-1",
			Rule: NewXMLParsingVulnerableToXXE(),
			Src:  SampleVulnerableJavaXMLParsingVulnerableToXXE,
			Findings: []engine.Finding{
				{
					CodeSample: `XMLReader reader = XMLReaderFactory.createXMLReader();`,
					SourceLocation: engine.Location{
						Line:   4,
						Column: 21,
					},
				},
			},
		},
		{
			Name: "HS-JAVA-134",
			Rule: NewSQLInjection(),
			Src:  SampleVulnerableJavaSQLInjection,
			Findings: []engine.Finding{
				{
					CodeSample: "var pstmt = con.prepareStatement(\"select * from mytable where field01 = '\" + field01 + \"'\");",
					SourceLocation: engine.Location{
						Line:   14,
						Column: 50,
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
			Name: "HS-JAVA-134",
			Rule: NewSQLInjection(),
			Src:  SampleSafeJavaSQLInjection,
		},
	}
	testutil.TestSafeCode(t, testcases)
}
