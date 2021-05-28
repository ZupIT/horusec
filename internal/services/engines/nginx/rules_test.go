package nginx

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/internal/services/engines"
)

func TestNewRules(t *testing.T) {
	assert.IsType(t, NewRules(), &engines.RuleManager{})
}

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
	totalRules := rules()
	lenExpectedTotalRules := 4

	t.Run("should not exists duplicated ID in rules and return lenExpectedTotalRules in nginx", func(t *testing.T) {
		encountered := map[string]bool{}

		for _, rule := range totalRules {
			r, ok := rule.(text.TextRule)
			require.True(t, ok, "Expected TextRule type, got %T", rule)

			if encountered[r.ID] == true {
				msg := fmt.Sprintf(
					"This rules in Ngingx is duplicated ID(%s) => Name: %s, Description: %s, Type: %v", r.ID, r.Name, r.Description, r.Type,
				)
				assert.False(t, encountered[r.ID], msg)
			} else {
				// Record this element as an encountered element.
				encountered[r.ID] = true
			}
		}

		assert.Equal(t, len(totalRules), lenExpectedTotalRules, "totalRules in nginx is not equal the expected")
		assert.Equal(t, len(encountered), lenExpectedTotalRules, "encountered in nginx is not equal the expected")
	})
}
