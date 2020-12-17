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

package kubernetes

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/kubernetes/and"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/kubernetes/or"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/kubernetes/regular"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
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
	for index := range allRulesKubernetesAnd() {
		rules = append(rules, allRulesKubernetesAnd()[index])
	}

	for index := range allRulesKubernetesOr() {
		rules = append(rules, allRulesKubernetesOr()[index])
	}

	for index := range allRulesKubernetesRegular() {
		rules = append(rules, allRulesKubernetesRegular()[index])
	}

	return rules
}

func (r *Rules) GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error) {
	textUnit, err := text.LoadDirIntoSingleUnit(projectPath, r.getExtensions())
	logger.LogDebugJSON("Text Unit selected is: ", textUnit)
	return []engine.Unit{textUnit}, err
}

func (r *Rules) getExtensions() []string {
	return []string{".yaml", ".yml"}
}

func allRulesKubernetesRegular() []text.TextRule {
	return []text.TextRule{
		regular.NewKubernetesRegularHostIPC(),
		regular.NewKubernetesRegularHostPID(),
		regular.NewKubernetesRegularHostNetwork(),
	}
}

func allRulesKubernetesAnd() []text.TextRule {
	return []text.TextRule{
		and.NewKubernetesAndAllowPrivilegeEscalation(),
		and.NewKubernetesAndHostAliases(),
		and.NewKubernetesAndDockerSock(),
		and.NewKubernetesAndCapabilitySystemAdmin(),
		and.NewKubernetesAndPrivilegedContainer(),
	}
}

func allRulesKubernetesOr() []text.TextRule {
	return []text.TextRule{
		or.NewKubernetesOrSeccompUnconfined(),
	}
}
