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

package swift

import (
	"path/filepath"
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	tmpDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-SWIFT-6",
			Rule:     NewWeakMD5CryptoCipher(),
			Src:      SampleVulnerableHSSWIFT6,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-6"),
			Findings: []engine.Finding{
				{
					CodeSample: `import CryptoSwift`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tmpDir, "HS-SWIFT-6"),
						Line:     1,
						Column:   0,
					},
				},
			},
		},
		{
			Name:     "HS-SWIFT-24",
			Src:      SampleVulnerableHSSWIFT24,
			Rule:     NewSQLInjection(),
			Filename: filepath.Join(tmpDir, "HS-SWIFT-24"),
			Findings: []engine.Finding{
				{
					CodeSample: `let err = SD.executeChange("SELECT * FROM User where user="+ valuesFromInput) {`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tmpDir, "HS-SWIFT-24"),
						Line:     2,
						Column:   13,
					},
				},
			},
		},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	tmpDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-SWIFT-6",
			Rule:     NewWeakMD5CryptoCipher(),
			Src:      SampleSafeHSSWIFT6,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-6"),
		},
		{
			Name:     "HS-SWIFT-24",
			Rule:     NewSQLInjection(),
			Src:      SampleSafeHSSWIFT24,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-24"),
		},
		{
			Name:     "HS-SWIFT-24",
			Rule:     NewSQLInjection(),
			Src:      Sample2SafeHSSWIFT24,
			Filename: filepath.Join(tmpDir, "HS-SWIFT-24"),
		},
	}
	testutil.TestSafeCode(t, testcases)
}
