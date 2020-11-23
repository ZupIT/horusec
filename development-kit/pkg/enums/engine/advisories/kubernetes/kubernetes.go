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
package kubernetes

import (
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/kubernetes/and"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/kubernetes/or"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/kubernetes/regular"
)

func AllRulesKubernetesRegular() []text.TextRule {
	return []text.TextRule{
		regular.NewKubernetesRegularHostIPC(),
		regular.NewKubernetesRegularHostPID(),
		regular.NewKubernetesRegularHostNetwork(),
	}
}

func AllRulesKubernetesAnd() []text.TextRule {
	return []text.TextRule{
		and.NewKubernetesAndAllowPrivilegeEscalation(),
		and.NewKubernetesAndHostAliases(),
		and.NewKubernetesAndDockerSock(),
		and.NewKubernetesAndCapabilitySystemAdmin(),
		and.NewKubernetesAndPrivilegedContainer(),
	}
}

func AllRulesKubernetesOr() []text.TextRule {
	return []text.TextRule{
		or.NewKubernetesOrSeccompUnconfined(),
	}
}
