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

package testutil

import (
	"testing"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	enginesenum "github.com/ZupIT/horusec/internal/enums/engines"
)

func TestVulnerableCode(t *testing.T, testcases []*RuleTestCase) {
	for _, tt := range testcases {
		t.Run(tt.Name, func(t *testing.T) {
			findings := executeRule(t, tt)
			assert.Len(t, findings, len(tt.Findings), "Expected equal issues on vulnerable code")
			assert.Equal(t, tt.Name, tt.Rule.ID, "Test case rule name is not match with rule id")
			assertExpectedFindingAndRuleCase(t, findings, tt)
		})
	}
}

// nolint
func assertExpectedFindingAndRuleCase(t *testing.T, findings []engine.Finding, tt *RuleTestCase) {
	for idx, finding := range findings {
		expected := tt.Findings[idx]
		assert.Equal(t, expected.CodeSample, finding.CodeSample)
		assert.Equal(t, expected.SourceLocation, finding.SourceLocation)
		assert.Equal(t, tt.Rule.ID, finding.ID)
		assert.Equal(t, tt.Rule.Name, finding.Name)
		assert.Equal(t, tt.Rule.Severity, finding.Severity)
		assert.Equal(t, tt.Rule.Confidence, finding.Confidence)
		assert.Equal(t, tt.Rule.Description, finding.Description)
	}
}

func TestSafeCode(t *testing.T, testcases []*RuleTestCase) {
	for _, tt := range testcases {
		t.Run(tt.Name, func(t *testing.T) {
			Findings := executeRule(t, tt)
			assert.Empty(t, Findings, "Expected not issues on safe code to Rule %s", tt.Name)
			assert.Equal(t, tt.Name, tt.Rule.ID)
		})
	}
}

func executeRule(tb testing.TB, tt *RuleTestCase) []engine.Finding {
	textFile, err := text.NewTextFile("", []byte(tt.Src))
	require.Nil(tb, err, "Expected nil error to create text file")

	unit := text.TextUnit{
		Files: []text.TextFile{
			textFile,
		},
	}

	return engine.RunMaxUnitsByAnalysis(
		[]engine.Unit{unit}, []engine.Rule{tt.Rule}, enginesenum.DefaultMaxUnitsPerAnalysis,
	)
}

type RuleTestCase struct {
	Name     string
	Src      string
	Rule     text.TextRule
	Findings []engine.Finding
}
