package customrules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	customRulesEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/custom_rules"
)

type IService interface {
	GetCustomRulesByTool(tool tools.Tool) []engine.Rule
}

type Service struct {
	config            cliConfig.IConfig
	customRulesByTool map[tools.Tool][]engine.Rule
}

func NewCustomRulesService(config cliConfig.IConfig) IService {
	service := &Service{
		config: config,
	}

	service.mapCustomRulesByTools()
	service.setCustomRules()

	return service
}

func (s *Service) GetCustomRulesByTool(tool tools.Tool) []engine.Rule {
	return s.customRulesByTool[tool]
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

	s.customRulesByTool[customRules[index].Tool] = append(
		s.customRulesByTool[customRules[index].Tool], s.parseCustomRuleToTextRule(index, customRules),
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

func (s *Service) mapCustomRulesByTools() {
	s.customRulesByTool = map[tools.Tool][]engine.Rule{
		tools.HorusecCsharp:     {},
		tools.HorusecKubernetes: {},
		tools.HorusecLeaks:      {},
		tools.HorusecKotlin:     {},
		tools.HorusecNodejs:     {},
		tools.HorusecJava:       {},
	}
}
