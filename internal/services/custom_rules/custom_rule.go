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
	"regexp"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/ZupIT/horusec/internal/services/engines/csharp"
	"github.com/ZupIT/horusec/internal/services/engines/dart"
	"github.com/ZupIT/horusec/internal/services/engines/java"
	"github.com/ZupIT/horusec/internal/services/engines/javascript"
	"github.com/ZupIT/horusec/internal/services/engines/kotlin"
	"github.com/ZupIT/horusec/internal/services/engines/kubernetes"
	"github.com/ZupIT/horusec/internal/services/engines/leaks"
	"github.com/ZupIT/horusec/internal/services/engines/nginx"
)

type CustomRule struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Language    languages.Language    `json:"language"`
	Severity    severities.Severity   `json:"severity"`
	Confidence  confidence.Confidence `json:"confidence"`
	Type        MatchType             `json:"type"`
	Expressions []string              `json:"expressions"`
}

func (c *CustomRule) Validate() error {
	return validation.ValidateStruct(c,
		validation.Field(&c.ID, validation.Required, ruleIDValidator{
			language: c.Language,
		}),
		validation.Field(&c.Language, validation.Required, validation.In(languages.CSharp, languages.Dart, languages.Java,
			languages.Kotlin, languages.Yaml, languages.Leaks, languages.Javascript, languages.Nginx)),
		validation.Field(&c.Severity, validation.Required, validation.In(severities.Info, severities.Unknown,
			severities.Low, severities.Medium, severities.High, severities.Critical)),
		validation.Field(&c.Confidence, validation.Required, validation.In(confidence.Low,
			confidence.Medium, confidence.High)),
		validation.Field(&c.Type, validation.Required, validation.In(Regular,
			OrMatch, AndMatch, NotMatch)),
	)
}

func (c *CustomRule) GetRuleType() text.MatchType {
	switch c.Type {
	case Regular:
		return text.Regular
	case OrMatch:
		return text.OrMatch
	case AndMatch:
		return text.AndMatch
	case NotMatch:
		return text.NotMatch
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

func (c *CustomRule) String() string {
	bytes, _ := json.Marshal(c)
	return string(bytes)
}

// ruleIDValidator implements validation.Rule interface.
type ruleIDValidator struct {
	language languages.Language
}

// Validate implements validation.Rule.Validate.
// nolint:funlen,exhaustive,gocyclo
func (r ruleIDValidator) Validate(value interface{}) error {
	id, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	language := strings.ToUpper(r.language.ToString())
	// TODO(matheus): Remove this. This is a terrible hack to convert C# to CSHARP.
	// The C# rules id use the prefix CHSARP but the enum value language.CSharp is
	// C#, so we need to convert to CSHARP nomenclature to follow already existed rules.
	if r.language == languages.CSharp {
		language = "CSHARP"
	}

	if match, _ := regexp.MatchString(fmt.Sprintf(`HS-%s-\d+`, language), id); !match {
		return fmt.Errorf("%s should match language name %s", value, r.language)
	}

	var rules []engine.Rule

	switch r.language {
	case languages.CSharp:
		rules = csharp.Rules()
	case languages.Dart:
		rules = dart.Rules()
	case languages.Java:
		rules = java.Rules()
	case languages.Kotlin:
		rules = kotlin.Rules()
	case languages.Yaml:
		rules = kubernetes.Rules()
	case languages.Leaks:
		rules = leaks.Rules()
	case languages.Javascript:
		rules = javascript.Rules()
	case languages.Nginx:
		rules = nginx.Rules()
	default:
		return fmt.Errorf("unsupported language %s", r.language)
	}

	return r.validateDuplicates(id, rules)
}

func (r ruleIDValidator) validateDuplicates(id string, rules []engine.Rule) error {
	for _, rule := range rules {
		// Custom rules is converted to text.Rule, so we only need
		// to check duplicates in text.Rule rules.
		if r, ok := rule.(*text.Rule); ok {
			if r.ID == id {
				return fmt.Errorf("duplicate rule id %s", id)
			}
		}
	}
	return nil
}
