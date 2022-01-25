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
			Name:     "HS-NGINX-1",
			Rule:     NewIncludeXFrameOptionsHeader(),
			Src:      SampleVulnerableHSNGINX1,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-1", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-1", ".test")),
						Line:     0,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-NGINX-2",
			Rule:     NewIncludeXContentTypeOptionsHeader(),
			Src:      SampleVulnerableHSNGINX2,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-2", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-2", ".test")),
						Line:     0,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-NGINX-3",
			Rule:     NewIncludeContentSecurityPolicyHeader(),
			Src:      SampleVulnerableHSNGINX3,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-3", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-3", ".test")),
						Line:     0,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-NGINX-4",
			Rule:     NewIncludeServerTokensOff(),
			Src:      SampleVulnerableHSNGINX4,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-4", ".test")),
			Findings: []engine.Finding{
				{
					CodeSample: "",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-4", ".test")),
						Line:     0,
						Column:   0,
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
			Name:     "HS-NGINX-1",
			Rule:     NewIncludeXFrameOptionsHeader(),
			Src:      SampleSafeHSNGINX1,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-1", ".test")),
		},
		{
			Name:     "HS-NGINX-2",
			Rule:     NewIncludeXContentTypeOptionsHeader(),
			Src:      SampleSafeHSNGINX2,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-2", ".test")),
		},
		{
			Name:     "HS-NGINX-3",
			Rule:     NewIncludeContentSecurityPolicyHeader(),
			Src:      SampleSafeHSNGINX3,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-3", ".test")),
		},
		{
			Name:     "HS-NGINX-4",
			Rule:     NewIncludeServerTokensOff(),
			Src:      SampleSafeHSNGINX4,
			Filename: filepath.Join(tempDir, fmt.Sprintf("%s%s", "HS-NGINX-4", ".test")),
		},
	}

	testutil.TestSafeCode(t, testcases)
}
