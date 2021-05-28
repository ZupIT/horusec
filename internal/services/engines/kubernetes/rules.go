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
	"github.com/ZupIT/horusec/internal/services/engines"
	"github.com/ZupIT/horusec/internal/services/engines/kubernetes/and"
	"github.com/ZupIT/horusec/internal/services/engines/kubernetes/or"
	"github.com/ZupIT/horusec/internal/services/engines/kubernetes/regular"
)

func NewRules() *engines.RuleManager {
	return engines.NewRuleManager(rules(), extensions())
}

func extensions() []string {
	return []string{".yaml", ".yml"}
}

func rules() []engine.Rule {
	return []engine.Rule{
		// Regular rules
		regular.NewKubernetesRegularHostIPC(),
		regular.NewKubernetesRegularHostPID(),
		regular.NewKubernetesRegularHostNetwork(),

		// And rules
		and.NewKubernetesAndAllowPrivilegeEscalation(),
		and.NewKubernetesAndHostAliases(),
		and.NewKubernetesAndDockerSock(),
		and.NewKubernetesAndCapabilitySystemAdmin(),
		and.NewKubernetesAndPrivilegedContainer(),

		// Or rules
		or.NewKubernetesOrSeccompUnconfined(),
	}
}
