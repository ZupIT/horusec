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
	cliConfig "github.com/ZupIT/horusec/config"
	customRulesEntities "github.com/ZupIT/horusec/internal/entities/custom_rules"
)

type IService interface {
	GetCustomRulesByLanguage(tool languages.Language) []engine.Rule
}

type Service struct {
	config            cliConfig.IConfig
	customRulesByTool map[languages.Language][]engine.Rule
}

func NewCustomRulesService(config cliConfig.IConfig) IService {
	service := &Service{
		config: config,
	}

	service.mapCustomRulesByLanguage()
	service.setCustomRules()

	return service
}

func (s *Service) GetCustomRulesByLanguage(lang languages.Language) []engine.Rule {
	return s.customRulesByTool[lang]
}

func (s *Service) setCustomRules() {
	if s.config.GetCustomRulesPath() == "" {
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
	file, err := os.Open(s.config.GetCustomRulesPath())
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
