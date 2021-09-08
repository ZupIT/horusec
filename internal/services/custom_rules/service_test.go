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
		config.CustomRulesPath = "./custom_rules_example.json"

		service := NewCustomRulesService(config)

		assert.Len(t, service.Load(languages.CSharp), 1)
		assert.Len(t, service.Load(languages.Dart), 1)
		assert.Len(t, service.Load(languages.Java), 1)
		assert.Len(t, service.Load(languages.Kotlin), 1)
		assert.Len(t, service.Load(languages.Yaml), 1)
		assert.Len(t, service.Load(languages.Leaks), 1)
		assert.Len(t, service.Load(languages.Javascript), 1)
	})

	t.Run("should return error when opening json file", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.CustomRulesPath = "./test.json"

		service := NewCustomRulesService(config)

		rules := service.Load(languages.Leaks)

		assert.Len(t, rules, 0)
	})

	t.Run("should success return invalid custom rule", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.CustomRulesPath = "./custom_rules_example_invalid.json"

		service := NewCustomRulesService(config)

		rules := service.Load(languages.Leaks)

		assert.Len(t, rules, 0)
	})
}
