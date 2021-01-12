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
package dart

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/dart/and"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/dart/or"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/dart/regular"
)

type Interface interface {
	GetAllRules() []engine.Rule
	GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error)
}

type Rules struct{}

func NewRules() Interface {
	return &Rules{}
}

func (r *Rules) GetAllRules() (rules []engine.Rule) {
	for _, rule := range allRulesDartAnd() {
		rules = append(rules, rule)
	}

	for _, rule := range allRulesDartOr() {
		rules = append(rules, rule)
	}

	for _, rule := range allRulesDartRegular() {
		rules = append(rules, rule)
	}

	return rules
}

func allRulesDartRegular() []text.TextRule {
	return []text.TextRule{
		regular.NewDartRegularXSSAttack(),
		regular.NewDartRegularNoLogSensitive(),
		regular.NewDartRegularWeakHashingFunctionMd5OrSha1(),
		regular.NewDartRegularNoUseSelfSignedCertificate(),
	}
}

func allRulesDartAnd() []text.TextRule {
	return []text.TextRule{
		and.NewDartAndUsageLocalDataWithoutCryptography(),
		and.NewDartAndNoSendSensitiveInformation(),
	}
}

func allRulesDartOr() []text.TextRule {
	return []text.TextRule{
		or.NewDartOrNoUseConnectionWithoutSSL(),
	}
}

func (r *Rules) GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error) {
	textUnit, err := text.LoadDirIntoSingleUnit(projectPath, r.getExtensions())
	return []engine.Unit{textUnit}, err
}

func (r *Rules) getExtensions() []string {
	return []string{".dart"}
}
