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

//nolint:lll // multiple regex is not possible broken lines
package regular

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewKubernetesRegularHostIPC() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "36255af0-2d6f-49c3-a2e7-e1f91d6c7652",
			Name:        "Host IPC",
			Description: "Sharing the host's IPC namespace allows container processes to communicate with processes on the host.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`hostIPC:\strue`),
		},
	}
}

func NewKubernetesRegularHostPID() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8408e039-b8d1-4104-bfc7-b58705843793",
			Name:        "Host PID",
			Description: "Sharing the host's PID namespace allows visibility of processes on the host, potentially leaking information such as environment variables and configuration.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`hostPID:\strue`),
		},
	}
}

func NewKubernetesRegularHostNetwork() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "db2df11f-9e58-45ce-94ef-861c6a8af361",
			Name:        "Host Network",
			Description: "Sharing the host's network namespace permits processes in the pod to communicate with processes bound to the host's loopback adapter.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`hostNetwork:\strue`),
		},
	}
}
