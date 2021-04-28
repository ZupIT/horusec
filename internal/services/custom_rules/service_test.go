package customrules

import (
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"

	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/config"
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

		assert.Len(t, service.GetCustomRulesByLanguage(languages.CSharp), 1)
		assert.Len(t, service.GetCustomRulesByLanguage(languages.Dart), 1)
		assert.Len(t, service.GetCustomRulesByLanguage(languages.Java), 1)
		assert.Len(t, service.GetCustomRulesByLanguage(languages.Kotlin), 1)
		assert.Len(t, service.GetCustomRulesByLanguage(languages.Yaml), 1)
		assert.Len(t, service.GetCustomRulesByLanguage(languages.Leaks), 1)
		assert.Len(t, service.GetCustomRulesByLanguage(languages.Javascript), 1)
	})

	t.Run("should return error when opening json file", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetCustomRulesPath("./test.json")

		service := NewCustomRulesService(config)

		rules := service.GetCustomRulesByLanguage(languages.Leaks)

		assert.Len(t, rules, 0)
	})

	t.Run("should success return invalid custom rule", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetCustomRulesPath("./custom_rules_example_invalid.json")

		service := NewCustomRulesService(config)

		rules := service.GetCustomRulesByLanguage(languages.Leaks)

		assert.Len(t, rules, 0)
	})
}
