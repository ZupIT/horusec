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

package kotlin

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/jvm"
)

type Interface interface {
	GetAllRules() (rules []engine.Rule)
	GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error)
}

type Rules struct {
	jvmRules jvm.Interface
}

func NewRules() Interface {
	return &Rules{
		jvmRules: jvm.NewRules(),
	}
}

func (r *Rules) GetAllRules() (rules []engine.Rule) {
	rules = r.jvmRules.GetAllRules(rules)
	return rules
}

func (r *Rules) GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error) {
	textUnit, err := text.LoadDirIntoSingleUnit(projectPath, r.getExtensions())
	return []engine.Unit{textUnit}, err
}

func (r *Rules) getExtensions() []string {
	return []string{".kt", ".kts"}
}

func allRulesKotlinRegular() []text.TextRule {
	return []text.TextRule{}
}

func allRulesKotlinAnd() []text.TextRule {
	return []text.TextRule{}
}

func allRulesKotlinOr() []text.TextRule {
	return []text.TextRule{}
}
