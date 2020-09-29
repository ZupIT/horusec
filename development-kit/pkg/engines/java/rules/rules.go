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
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/java"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/jvm"
)

type Interface interface {
	GetAllRules() (rules []engine.Rule)
}

type Rules struct{}

func NewRules() Interface {
	return &Rules{}
}

func (r *Rules) GetAllRules() (rules []engine.Rule) {
	rules = r.addJavaRules(rules)
	rules = r.addJvmRules(rules)
	return rules
}

func (r *Rules) addJavaRules(rules []engine.Rule) []engine.Rule {
	for index := range java.AllRulesJavaAnd() {
		rules = append(rules, java.AllRulesJavaAnd()[index])
	}
	for index := range java.AllRulesJavaOr() {
		rules = append(rules, java.AllRulesJavaOr()[index])
	}
	for index := range java.AllRulesJavaRegular() {
		rules = append(rules, java.AllRulesJavaRegular()[index])
	}
	return rules
}

func (r *Rules) addJvmRules(rules []engine.Rule) []engine.Rule {
	for index := range jvm.AllRulesJvmAnd() {
		rules = append(rules, jvm.AllRulesJvmAnd()[index])
	}
	for index := range jvm.AllRulesJvmOr() {
		rules = append(rules, jvm.AllRulesJvmOr()[index])
	}
	for index := range jvm.AllRulesJvmRegular() {
		rules = append(rules, jvm.AllRulesJvmRegular()[index])
	}
	return rules
}
