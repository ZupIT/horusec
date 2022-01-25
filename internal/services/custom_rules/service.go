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
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"

	"github.com/ZupIT/horusec/config"
)

// Service represents the custom rule service responsible to
// load custom rules from an configuration file.
type Service struct {
	config      *config.Config
	customRules map[languages.Language][]engine.Rule
}

// NewCustomRulesService create a new custom rule service with all rules
// loaded from configuration file path.
func NewCustomRulesService(cfg *config.Config) *Service {
	service := &Service{
		config: cfg,
		customRules: map[languages.Language][]engine.Rule{
			languages.CSharp:     make([]engine.Rule, 0),
			languages.Dart:       make([]engine.Rule, 0),
			languages.Java:       make([]engine.Rule, 0),
			languages.Kotlin:     make([]engine.Rule, 0),
			languages.Yaml:       make([]engine.Rule, 0),
			languages.Leaks:      make([]engine.Rule, 0),
			languages.Javascript: make([]engine.Rule, 0),
			languages.Nginx:      make([]engine.Rule, 0),
		},
	}
	return service.loadCustomRules()
}

// Load implements formatters.CustomRules
func (s *Service) Load(lang languages.Language) []engine.Rule {
	return s.customRules[lang]
}

func (s *Service) loadCustomRules() *Service {
	if s.config.CustomRulesPath == "" {
		return s
	}

	customRules, err := s.openCustomRulesJSONFile()
	if err != nil {
		logger.LogError("{HORUSEC_CLI} failed to get custom rules: ", err)
	}

	for index := range customRules {
		s.validateAndParseCustomRule(customRules[index])
	}

	return s
}

func (s *Service) validateAndParseCustomRule(rule *CustomRule) {
	if err := rule.Validate(); err != nil {
		errMsg := fmt.Sprintf("{HORUSEC_CLI} invalid custom rule: %s", rule.String())
		logger.LogError(errMsg, err)
		return
	}

	s.customRules[rule.Language] = append(
		s.customRules[rule.Language], s.parseCustomRuleToRule(rule),
	)
}

func (s *Service) openCustomRulesJSONFile() (customRules []*CustomRule, err error) {
	file, err := os.Open(s.config.CustomRulesPath)
	if err != nil {
		return nil, err
	}

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return customRules, json.Unmarshal(bytes, &customRules)
}

func (s *Service) parseCustomRuleToRule(rule *CustomRule) engine.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          rule.ID,
			Name:        rule.Name,
			Description: rule.Description,
			Severity:    rule.Severity.ToString(),
			Confidence:  rule.Confidence.ToString(),
		},
		Type:        rule.GetRuleType(),
		Expressions: rule.GetExpressions(),
	}
}
