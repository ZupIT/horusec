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

package kubernetes

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
			Name:     "HS-KUBERNETES-1",
			Rule:     NewAllowPrivilegeEscalation(),
			Src:      SampleVulnerableHSKUBERNETES1,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-2", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "allowPrivilegeEscalation: true",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-2", ".test")),
						Line:     10,
						Column:   1,
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
			Name:     "HS-KUBERNETES-1",
			Rule:     NewAllowPrivilegeEscalation(),
			Src:      SampleSafeHSKUBERNETES1,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-JAVASCRIPT-2", ".test")),
		},
	}

	testutil.TestSafeCode(t, testcases)
}
