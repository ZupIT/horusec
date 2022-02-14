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

package engines_test

import (
	"testing"

	"github.com/ZupIT/horusec-engine/text"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec/internal/services/engines"
	"github.com/ZupIT/horusec/internal/services/engines/csharp"
	"github.com/ZupIT/horusec/internal/services/engines/dart"
	"github.com/ZupIT/horusec/internal/services/engines/java"
	"github.com/ZupIT/horusec/internal/services/engines/javascript"
	"github.com/ZupIT/horusec/internal/services/engines/kotlin"
	"github.com/ZupIT/horusec/internal/services/engines/kubernetes"
	"github.com/ZupIT/horusec/internal/services/engines/leaks"
	"github.com/ZupIT/horusec/internal/services/engines/nginx"
	"github.com/ZupIT/horusec/internal/services/engines/swift"
)

func TestGetRules(t *testing.T) {
	testcases := []struct {
		engine             string
		manager            *engines.RuleManager
		expectedTotalRules int
	}{
		{
			engine:             "Javascript",
			manager:            javascript.NewRules(),
			expectedTotalRules: 53,
		},
		{
			engine:             "Nginx",
			manager:            nginx.NewRules(),
			expectedTotalRules: 4,
		},
		{
			engine:             "Leaks",
			manager:            leaks.NewRules(),
			expectedTotalRules: 28,
		},
		{
			engine:             "Kubernetes",
			manager:            kubernetes.NewRules(),
			expectedTotalRules: 9,
		},
		{
			engine:             "Kotlin",
			manager:            kotlin.NewRules(),
			expectedTotalRules: 40,
		},
		{
			engine:             "Java",
			manager:            java.NewRules(),
			expectedTotalRules: 181,
		},
		{
			engine:             "Dart",
			manager:            dart.NewRules(),
			expectedTotalRules: 17,
		},
		{
			engine:             "Csharp",
			manager:            csharp.NewRules(),
			expectedTotalRules: 74,
		},
		{
			engine:             "Swift",
			manager:            swift.NewRules(),
			expectedTotalRules: 23,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.engine, func(t *testing.T) {
			rules := tt.manager.GetAllRules()
			expressions := 0
			rulesID := map[string]bool{}

			for _, rule := range rules {
				r, ok := rule.(*text.Rule)
				require.True(t, ok, "Expected rule type of text.Rule, got %T", rule)
				expressions += len(r.Expressions)

				if rulesID[r.ID] == true {
					t.Errorf(
						"Rule in %s is duplicated ID(%s) => Name: %s, Description: %s, Type: %v", tt.engine, r.ID, r.Name, r.Description, r.Type,
					)
				} else {
					// Record this element as an encountered element.
					rulesID[r.ID] = true
				}

			}

			assert.Greater(t, len(rules), 0)
			assert.Greater(t, expressions, 0)

			assert.Equal(t, len(rules), tt.expectedTotalRules, "Total rules is not equal the expected")
			assert.Equal(t, len(rulesID), tt.expectedTotalRules, "Rules ID is not equal the expected")
		})
	}
}
