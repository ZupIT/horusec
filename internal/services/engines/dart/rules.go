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

package dart

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/internal/services/engines/dart/and"
	"github.com/ZupIT/horusec/internal/services/engines/dart/or"
	"github.com/ZupIT/horusec/internal/services/engines/dart/regular"
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
		regular.NewDartRegularNoUseBiometricsTypeAndroid(),
		regular.NewDartRegularNoListClipboardChanges(),
		regular.NewDartRegularSQLInjection(),
		regular.NewDartRegularNoUseNSTemporaryDirectory(),
		regular.NewDartRegularNoUseCipherMode(),
		regular.NewDartRegularCorsAllowOriginWildCard(),
		regular.NewDartRegularUsingShellInterpreterWhenExecutingOSCommand(),
	}
}

func allRulesDartAnd() []text.TextRule {
	return []text.TextRule{
		and.NewDartAndUsageLocalDataWithoutCryptography(),
		and.NewDartAndNoSendSensitiveInformation(),
		and.NewDartAndNoUseBiometricsTypeIOS(),
		and.NewDartAndXmlReaderExternalEntityExpansion(),
	}
}

func allRulesDartOr() []text.TextRule {
	return []text.TextRule{
		or.NewDartOrNoUseConnectionWithoutSSL(),
		or.NewDartOrSendSMS(),
	}
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
	return []string{".dart"}
}
