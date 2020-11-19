// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package rules

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/csharp"
)

type Interface interface {
	GetAllRules() (rules []engine.Rule)
}

type Rules struct{}

func NewRules() Interface {
	return &Rules{}
}

func (r *Rules) GetAllRules() (rules []engine.Rule) {
	for index := range csharp.AllRulesCsharpAnd() {
		rules = append(rules, csharp.AllRulesCsharpAnd()[index])
	}
	for index := range csharp.AllRulesCsharpOr() {
		rules = append(rules, csharp.AllRulesCsharpOr()[index])
	}
	for index := range csharp.AllRulesCsharpRegular() {
		rules = append(rules, csharp.AllRulesCsharpRegular()[index])
	}
	return rules
}
