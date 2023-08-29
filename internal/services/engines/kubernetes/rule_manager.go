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
)

func NewRules() *engines.RuleManager {
	return engines.NewRuleManager(Rules(), extensions())
}

func extensions() []string {
	return []string{".yaml", ".yml"}
}

// Rules return all Rules registred to Kubernetes engine.
func Rules() []engine.Rule {
	return []engine.Rule{
		// Regular rules
		NewHostIPC(),
		NewHostPID(),
		NewHostNetwork(),

		// And rules
		NewAllowPrivilegeEscalation(),
		NewHostAliases(),
		NewDockerSock(),
		NewCapabilitySystemAdmin(),
		NewPrivilegedContainer(),

		// Or rules
		NewSeccompUnconfined(),

		// Github Actions Rules
		NewGHActionsSensitiveInformationExposureWithEcho(),
	}
}
