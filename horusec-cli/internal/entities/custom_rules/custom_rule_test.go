package customrules

import (
	"testing"

	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	customRulesEnums "github.com/ZupIT/horusec/horusec-cli/internal/enums/custom_rules"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	t.Run("should return no errors when valid custom rule", func(t *testing.T) {
		customRule := CustomRule{
			ID:          uuid.New(),
			Name:        "test",
			Description: "test",
			Severity:    severity.Low,
			Confidence:  confidence.Low,
			Type:        customRulesEnums.OrMatch,
			Expressions: []string{""},
			Tool:        "HorusecLeaks",
		}

		assert.NoError(t, customRule.Validate())
	})

	t.Run("should return error when invalid custom", func(t *testing.T) {
		customRule := CustomRule{}
		assert.Error(t, customRule.Validate())
	})
}

func TestGetRuleType(t *testing.T) {
	t.Run("should return regular type", func(t *testing.T) {
		customRule := CustomRule{
			Type: customRulesEnums.Regular,
		}

		assert.Equal(t, text.Regular, customRule.GetRuleType())
	})

	t.Run("should return regular type", func(t *testing.T) {
		customRule := CustomRule{}

		assert.Equal(t, text.Regular, customRule.GetRuleType())
	})

	t.Run("should return or type", func(t *testing.T) {
		customRule := CustomRule{
			Type: customRulesEnums.OrMatch,
		}

		assert.Equal(t, text.OrMatch, customRule.GetRuleType())
	})

	t.Run("should return and type", func(t *testing.T) {
		customRule := CustomRule{
			Type: customRulesEnums.AndMatch,
		}

		assert.Equal(t, text.AndMatch, customRule.GetRuleType())
	})
}

func TestGetExpressions(t *testing.T) {
	t.Run("should success get regex expressions", func(t *testing.T) {
		customRule := CustomRule{
			Expressions: []string{"test", "test"},
		}

		assert.Len(t, customRule.GetExpressions(), 2)
	})

	t.Run("should log error when failed to compile expression", func(t *testing.T) {
		customRule := CustomRule{
			Expressions: []string{"^\\/(?!\\/)(.*?)"},
		}

		assert.Len(t, customRule.GetExpressions(), 0)
	})
}

func TestToString(t *testing.T) {
	t.Run("should log error when failed to compile expression", func(t *testing.T) {
		customRule := CustomRule{ID: uuid.New()}

		assert.NotEmpty(t, customRule.ToString())
	})
}
