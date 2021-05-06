package customrules

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	customRulesEnums "github.com/ZupIT/horusec/horusec-cli/internal/enums/custom_rules"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
)

type CustomRule struct {
	ID          uuid.UUID                 `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Severity    severity.Severity         `json:"severity"`
	Confidence  confidence.Confidence     `json:"confidence"`
	Type        customRulesEnums.MathType `json:"type"`
	Expressions []string                  `json:"expressions"`
	Tool        tools.Tool                `json:"tool"`
}

func (c *CustomRule) Validate() error {
	return validation.ValidateStruct(c,
		validation.Field(&c.ID, validation.Required, is.UUID),
		validation.Field(&c.Severity, validation.Required, validation.In(severity.Info, severity.Unknown,
			severity.Low, severity.Medium, severity.High, severity.Critical)),
		validation.Field(&c.Confidence, validation.Required, validation.In(
			confidence.Low, confidence.Medium, confidence.High)),
		validation.Field(&c.Type, validation.Required, validation.In(customRulesEnums.Regular,
			customRulesEnums.OrMatch, customRulesEnums.AndMatch)),
		validation.Field(&c.Tool, validation.Required, validation.In(tools.HorusecCsharp, tools.HorusecJava,
			tools.HorusecKotlin, tools.HorusecKubernetes, tools.HorusecLeaks, tools.HorusecNodejs, tools.HorusecNginx)),
	)
}

func (c *CustomRule) GetRuleType() text.MatchType {
	switch c.Type {
	case customRulesEnums.Regular:
		return text.Regular
	case customRulesEnums.OrMatch:
		return text.OrMatch
	case customRulesEnums.AndMatch:
		return text.AndMatch
	}

	return text.Regular
}

func (c *CustomRule) GetExpressions() (expressions []*regexp.Regexp) {
	for _, expression := range c.Expressions {
		regex, err := regexp.Compile(expression)
		if err != nil {
			logger.LogError(fmt.Sprintf("{HORUSEC_CLI} failed to compile custom rule regex: %s", expression), err)
		} else {
			expressions = append(expressions, regex)
		}
	}

	return expressions
}

func (c *CustomRule) ToString() string {
	bytes, _ := json.Marshal(c)
	return string(bytes)
}
