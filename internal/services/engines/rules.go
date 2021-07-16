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

package engines

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

// RuleManager is a generic implementation of formatters.RuleManager
// that can be reused between all engines to load rules
type RuleManager struct {
	rules      []engine.Rule
	extensions []string
}

func NewRuleManager(rules []engine.Rule, extensions []string) *RuleManager {
	return &RuleManager{
		rules:      rules,
		extensions: extensions,
	}
}

func (r *RuleManager) GetAllRules() []engine.Rule {
	return r.rules
}

//nolint:gomnd // magic number
func (r *RuleManager) GetTextUnitByRulesExt(src string) ([]engine.Unit, error) {
	textUnits, err := text.LoadDirIntoMultiUnit(src, 5, r.extensions)
	if err != nil {
		return []engine.Unit{}, err
	}
	return r.parseTextUnitsToUnits(textUnits), nil
}

func (r *RuleManager) parseTextUnitsToUnits(textUnits []text.TextUnit) []engine.Unit {
	units := make([]engine.Unit, 0, len(textUnits))
	for _, t := range textUnits {
		units = append(units, t)
	}
	return units
}
