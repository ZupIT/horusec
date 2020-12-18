package customrules

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"

	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
)

func TestNewCustomRulesService(t *testing.T) {
	t.Run("should success create new custom rules service", func(t *testing.T) {
		service := NewCustomRulesService(&cliConfig.Config{})
		assert.NotEmpty(t, service)
	})
}

func TestGetCustomRulesByTool(t *testing.T) {
	t.Run("should success get rules by tool", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetCustomRulesPath("./custom_rules_example.json")

		service := NewCustomRulesService(config)

		rules := service.GetCustomRulesByTool(tools.HorusecCsharp)

		assert.Len(t, rules, 1)
	})

	t.Run("should return error when opening json file", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetCustomRulesPath("./test.json")

		service := NewCustomRulesService(config)

		rules := service.GetCustomRulesByTool(tools.HorusecCsharp)

		assert.Len(t, rules, 0)
	})

	t.Run("should success return invalid custom rule", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetCustomRulesPath("./custom_rules_example_invalid.json")

		service := NewCustomRulesService(config)

		rules := service.GetCustomRulesByTool(tools.HorusecCsharp)

		assert.Len(t, rules, 0)
	})
}
