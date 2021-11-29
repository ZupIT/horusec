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

package customrules_test

import (
	"path/filepath"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	customrules "github.com/ZupIT/horusec/internal/services/custom_rules"
)

func TestNewCustomRulesService(t *testing.T) {
	service := customrules.NewCustomRulesService(config.New())

	assert.NotEmpty(t, service)
	assertEmptyRulesForAllLanguages(t, service)
}

func TestGetCustomRulesByTool(t *testing.T) {
	t.Run("should success load custom rules from file", func(t *testing.T) {
		cfg := config.New()
		cfg.CustomRulesPath = filepath.Join(".", "custom_rules_example.json")

		service := customrules.NewCustomRulesService(cfg)

		assert.Len(t, service.Load(languages.CSharp), 1)
		assert.Len(t, service.Load(languages.Dart), 1)
		assert.Len(t, service.Load(languages.Java), 1)
		assert.Len(t, service.Load(languages.Kotlin), 1)
		assert.Len(t, service.Load(languages.Yaml), 1)
		assert.Len(t, service.Load(languages.Leaks), 1)
		assert.Len(t, service.Load(languages.Javascript), 1)
	})

	t.Run("should use empty rules for all languages when file does not exists", func(t *testing.T) {
		cfg := config.New()
		cfg.CustomRulesPath = filepath.Join(".", "test.json")

		service := customrules.NewCustomRulesService(cfg)

		assertEmptyRulesForAllLanguages(t, service)
	})

	t.Run("should use empty rules for all languages when file is in invalid format", func(t *testing.T) {
		cfg := config.New()
		cfg.CustomRulesPath = filepath.Join(".", "custom_rules_example_invalid.json")

		service := customrules.NewCustomRulesService(cfg)

		assertEmptyRulesForAllLanguages(t, service)
	})
}

func assertEmptyRulesForAllLanguages(t *testing.T, service *customrules.Service) {
	for _, lang := range languages.Values() {
		assert.Empty(t, service.Load(lang), "Expected empty default custom rules to language %s", lang)
	}
}
