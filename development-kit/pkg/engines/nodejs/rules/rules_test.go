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

package rules

import (
	"testing"

	"github.com/ZupIT/horusec-engine/text"
	"github.com/stretchr/testify/assert"
)

func TestNewRules(t *testing.T) {
	assert.IsType(t, NewRules(), &Rules{})
}

func TestRules_GetAllRules(t *testing.T) {
	t.Run("Should return all rules enable", func(t *testing.T) {
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
