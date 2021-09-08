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
	"io/ioutil"
	"os"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/config"
	customRulesEntities "github.com/ZupIT/horusec/internal/entities/custom_rules"
)

type Service struct {
	config            *config.Config
	customRulesByTool map[languages.Language][]engine.Rule
}

func NewCustomRulesService(cfg *config.Config) *Service {
	service := &Service{
		config: cfg,
	}

	service.mapCustomRulesByLanguage()
	service.setCustomRules()

	return service
}

func (s *Service) Load(lang languages.Language) []engine.Rule {
	return s.customRulesByTool[lang]
}

func (s *Service) setCustomRules() {
	if s.config.CustomRulesPath == "" {
		return
	}

	customRules, err := s.openCustomRulesJSONFile()
	if err != nil {
		logger.LogError("{HORUSEC_CLI} failed to get custom rules: ", err)
	}

	for index := range customRules {
		s.validateAndParseCustomRule(index, customRules)
	}
}

func (s *Service) validateAndParseCustomRule(index int, customRules []customRulesEntities.CustomRule) {
	if err := customRules[index].Validate(); err != nil {
		errMsg := fmt.Sprintf("{HORUSEC_CLI} invalid custom rule: %s", customRules[index].ToString())
		logger.LogError(errMsg, err)
		return
	}

	s.customRulesByTool[customRules[index].Language] = append(
		s.customRulesByTool[customRules[index].Language], s.parseCustomRuleToTextRule(index, customRules),
	)
}

func (s *Service) openCustomRulesJSONFile() (customRules []customRulesEntities.CustomRule, err error) {
	file, err := os.Open(s.config.CustomRulesPath)
	if err != nil {
		return nil, err
	}

	byteValue, _ := ioutil.ReadAll(file)
	return customRules, json.Unmarshal(byteValue, &customRules)
}

func (s *Service) parseCustomRuleToTextRule(index int, customRules []customRulesEntities.CustomRule) text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          customRules[index].ID.String(),
			Name:        customRules[index].Name,
			Description: customRules[index].Description,
			Severity:    customRules[index].Severity.ToString(),
			Confidence:  customRules[index].Confidence.ToString(),
		},
		Type:        customRules[index].GetRuleType(),
		Expressions: customRules[index].GetExpressions(),
	}
}

func (s *Service) mapCustomRulesByLanguage() {
	s.customRulesByTool = map[languages.Language][]engine.Rule{
		languages.CSharp:     {},
		languages.Dart:       {},
		languages.Java:       {},
		languages.Kotlin:     {},
		languages.Yaml:       {},
		languages.Leaks:      {},
		languages.Javascript: {},
		languages.Nginx:      {},
	}
}
