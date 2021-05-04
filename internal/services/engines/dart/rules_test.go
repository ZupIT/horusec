// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package dart

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-engine/text"
)

func TestRules_GetAllRules(t *testing.T) {
	t.Run("should return all rules enable", func(t *testing.T) {
		rules := NewRules().GetAllRules()
		totalRegexes := 0

		for i := range rules {
			textRule := rules[i].(text.TextRule)
			totalRegexes += len(textRule.Expressions)
		}

		assert.Greater(t, len(rules), 0)
		assert.Greater(t, totalRegexes, 0)
	})
}
func TestRulesEnum(t *testing.T) {
	var totalRules []text.TextRule

	totalRules = append(totalRules, allRulesDartAnd()...)
	totalRules = append(totalRules, allRulesDartOr()...)
	totalRules = append(totalRules, allRulesDartRegular()...)
	lenExpectedTotalRules := 17

	t.Run("Should not exists duplicated ID in rules and return lenExpectedTotalRules in dart", func(t *testing.T) {
		encountered := map[string]bool{}

		for v := range totalRules {
			if encountered[totalRules[v].ID] == true {
				msg := fmt.Sprintf("This rules in dart is duplicated ID(%s) => Name: %s, Description: %s, Type: %v", totalRules[v].ID, totalRules[v].Name, totalRules[v].Description, totalRules[v].Type)
				assert.False(t, encountered[totalRules[v].ID], msg)
			} else {
				// Record this element as an encountered element.
				encountered[totalRules[v].ID] = true
			}
		}
		assert.Equal(t, len(totalRules), lenExpectedTotalRules, "totalRules in dart is not equal the expected")
		assert.Equal(t, len(encountered), lenExpectedTotalRules, "encountered in dart is not equal the expected")
	})
}
