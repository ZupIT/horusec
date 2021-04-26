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

//nolint:lll multiple regex is not possible broken lines
package nginx

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/nginx/not"
)

type Interface interface {
	GetAllRules() (rules []engine.Rule)
	GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error)
}

type Rules struct{}

func NewRules() Interface {
	return &Rules{}
}

func (r *Rules) GetAllRules() (rules []engine.Rule) {
	for _, rule := range allNginxNotRules() {
		rules = append(rules, rule)
	}

	return rules
}

func (r *Rules) GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error) {
	textUnits, err := text.LoadDirIntoMultiUnit(projectPath, 5, r.getExtensions())
	if err != nil {
		return []engine.Unit{}, err
	}
	return r.parseTextUnitsToUnits(textUnits), nil
}

func (r *Rules) parseTextUnitsToUnits(textUnits []text.TextUnit) (units []engine.Unit) {
	for index := range textUnits {
		units = append(units, textUnits[index])
	}
	return units
}

func (r *Rules) getExtensions() []string {
	return []string{".nginx", "nginxconf", ".vhost"}
}

func allNginxNotRules() []text.TextRule {
	return []text.TextRule{
		not.NewNginxNotIncludeXFrameOptionsHeader(),
	}
}
