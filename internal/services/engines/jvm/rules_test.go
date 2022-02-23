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

package jvm

import (
	"path/filepath"
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	tempDir := t.TempDir()

	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-JVM-24",
			Rule:     NewBase64Decode(),
			Src:      SampleVulnerableHSJVM24,
			Filename: filepath.Join(tempDir, "HS-JVM-24.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `byte[] decodedValue = Base64.getDecoder().decode(value);`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-24.test"),
						Line:     4,
						Column:   43,
					},
				},
			},
		},
		{
			Name:     "HS-JVM-38",
			Rule:     NewBase64Encode(),
			Src:      SampleVulnerableHSJVM38,
			Filename: filepath.Join(tempDir, "HS-JVM-38.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `Base64.getEncoder().encodeToString(input.getBytes());`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-38.test"),
						Line:     5,
						Column:   21,
					},
				},
				{
					CodeSample: `String encodedString = new String(base64.encode(input.getBytes()));`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-JVM-38.test"),
						Line:     8,
						Column:   42,
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
			Name:     "HS-JVM-38",
			Rule:     NewBase64Encode(),
			Src:      SampleSafeHSJVM38,
			Filename: filepath.Join(tempDir, "HS-JVM-38.test"),
		},
		{
			Name:     "HS-JVM-38",
			Rule:     NewBase64Encode(),
			Src:      Sample2SafeHSJVM38,
			Filename: filepath.Join(tempDir, "HS-JVM-38.test"),
		},
		{
			Name:     "HS-JVM-24",
			Rule:     NewBase64Decode(),
			Src:      SampleSafeHSJVM24,
			Filename: filepath.Join(tempDir, "HS-JVM-24.test"),
		},
	}

	testutil.TestSafeCode(t, testcases)
}
