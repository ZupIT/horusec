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
package or

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"regexp"
)

func NewKubernetesOrSeccompUnconfined() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9b26b361-7a92-465a-ae77-1c7122266823",
			Name:        "Seccomp Unconfined",
			Description: "Unconfined Seccomp profiles have full system call access.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`seccomp\.security\.alpha\.kubernetes\.io/[a-zA-Z-.]+: unconfined`),
			regexp.MustCompile(`[\[ ]seccomp\.security\.alpha\.kubernetes\.io/[a-zA-Z-.]+:unconfined[\] ]`),
		},
	}
}
