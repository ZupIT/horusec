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

package regular

import (
	"testing"

	"github.com/stretchr/testify/assert"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func parseTextUnitsToUnits(textUnits []text.TextUnit) (units []engine.Unit) {
	for index := range textUnits {
		units = append(units, textUnits[index])
	}
	return units
}

func TestNewNodeJSRegularAlertStatementsShouldNotBeUsed(t *testing.T) {
	t.Run("Should return vulnerability and code of line correctly", func(t *testing.T) {
		code := `
const text = "This line has no vulnerabilities";
alert("This line is vulnerable");
`
		rule := NewNodeJSRegularAlertStatementsShouldNotBeUsed()
		textFile, err := text.NewTextFile("test.js", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:          rule.ID,
			Name:        rule.Name,
			Severity:    rule.Severity,
			CodeSample:  `alert("This line is vulnerable");`,
			Confidence:  rule.Confidence,
			Description: rule.Description,
			SourceLocation: engine.Location{
				Filename: "test.js",
				Line:     3,
				Column:   0,
			},
		}, findings[0])
	})
	t.Run("Should return vulnerability and code of line correctly with spaces", func(t *testing.T) {
		code := `
const text = "This line has no vulnerabilities";
             alert("This line is vulnerable");
`
		rule := NewNodeJSRegularAlertStatementsShouldNotBeUsed()
		textFile, err := text.NewTextFile("test.js", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:          rule.ID,
			Name:        rule.Name,
			Severity:    rule.Severity,
			CodeSample:  `alert("This line is vulnerable");`,
			Confidence:  rule.Confidence,
			Description: rule.Description,
			SourceLocation: engine.Location{
				Filename: "test.js",
				Line:     3,
				Column:   12,
			},
		}, findings[0])
	})
	t.Run("Should return vulnerability and code of line correctly with inline", func(t *testing.T) {
		code := `
const text = "This line has no vulnerabilities";alert("This line is vulnerable");
`
		rule := NewNodeJSRegularAlertStatementsShouldNotBeUsed()
		textFile, err := text.NewTextFile("test.js", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:          rule.ID,
			Name:        rule.Name,
			Severity:    rule.Severity,
			CodeSample:  `const text = "This line has no vulnerabilities";alert("This line is vulnerable");`,
			Confidence:  rule.Confidence,
			Description: rule.Description,
			SourceLocation: engine.Location{
				Filename: "test.js",
				Line:     2,
				Column:   47,
			},
		}, findings[0])
	})
}
