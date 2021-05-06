package customrules

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec-engine/text"
	customRulesEnums "github.com/ZupIT/horusec/internal/enums/custom_rules"
)

type CustomRule struct {
	ID          uuid.UUID                 `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Language    languages.Language        `json:"language"`
	Severity    severities.Severity       `json:"severity"`
	Confidence  confidence.Confidence     `json:"confidence"`
	Type        customRulesEnums.MathType `json:"type"`
	Expressions []string                  `json:"expressions"`
}

func (c *CustomRule) Validate() error {
	return validation.ValidateStruct(c,
		validation.Field(&c.ID, validation.Required, is.UUID),
		validation.Field(&c.Language, validation.Required, validation.In(languages.CSharp, languages.Dart, languages.Java,
			languages.Kotlin, languages.Yaml, languages.Leaks, languages.Javascript)),
		validation.Field(&c.Severity, validation.Required, validation.In(severities.Info, severities.Unknown,
			severities.Low, severities.Medium, severities.High, severities.Critical)),
		validation.Field(&c.Confidence, validation.Required, validation.In(
			confidence.Low, confidence.Medium, confidence.High)),
		validation.Field(&c.Type, validation.Required, validation.In(customRulesEnums.Regular,
			customRulesEnums.OrMatch, customRulesEnums.AndMatch)),
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
