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
	"github.com/ZupIT/horusec/internal/services/engines"
	"github.com/ZupIT/horusec/internal/services/engines/nginx/not"
)

func NewRules() *engines.RuleManager {
	return engines.NewRuleManager(rules(), extensions())
}

func extensions() []string {
	return []string{".nginx", "nginxconf", ".vhost"}
}

func rules() []engine.Rule {
	return []engine.Rule{
		// Not rules
		not.NewNginxNotIncludeXFrameOptionsHeader(),
		not.NewNginxNotIncludeXContentTypeOptionsHeader(),
		not.NewNginxNotIncludeContentSecurityPolicyHeader(),
		not.NewNginxNotIncludeServerTokensOff(),
	}
}
