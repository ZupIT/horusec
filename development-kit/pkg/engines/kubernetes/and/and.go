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
package and

import (
	"regexp"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
)

func NewKubernetesAndAllowPrivilegeEscalation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1e0be755-5333-4a74-ade4-d23a95d58b54",
			Name:        "Allow Privilege Escalation",
			Description: "Privileged containers share namespaces with the host system, eschew cgroup restrictions, and do not offer any security. They should be used exclusively as a bundling and distribution mechanism for the code in the container, and not for isolation.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`allowPrivilegeEscalation:\strue`),
			regexp.MustCompile(`containers:`),
			regexp.MustCompile(`securityContext:`),
		},
	}
}

func NewKubernetesAndHostAliases() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fc601f5a-0dd9-472f-9476-24f12ef8e990",
			Name:        "Host Aliases",
			Description: "Managing /etc/hosts aliases can prevent the container from modifying the file after a pod's containers have already been started. DNS should be managed by the orchestrator.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`hostAliases:`),
			regexp.MustCompile(`ip:`),
			regexp.MustCompile(`hostnames:`),
		},
	}
}

func NewKubernetesAndDockerSock() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "89b452df-dfbd-487c-a6c6-9e002aac0823",
			Name:        "Docker Sock",
			Description: "Mounting the docker.socket leaks information about other containers and can allow container breakout.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`/var/run/docker\.sock`),
			regexp.MustCompile(`hostPath:`),
			regexp.MustCompile(`volumes:`),
		},
	}
}

func NewKubernetesAndCapabilitySystemAdmin() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3e68d755-e860-49db-84b4-65f323edb1f1",
			Name:        "Capability System Admin",
			Description: "CAP_SYS_ADMIN is the most privileged capability and should always be avoided.",
			Severity:    severity.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`-\sSYS_ADMIN`),
			regexp.MustCompile(`add:`),
			regexp.MustCompile(`capabilities:`),
			regexp.MustCompile(`securityContext:`),
			regexp.MustCompile(`(initContainers:|containers:)`),
		},
	}
}

func NewKubernetesAndPrivilegedContainer() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6deb1d82-7579-4e1b-9f1e-ed287e0eaccb",
			Name:        "Privileged Container",
			Description: "Privileged containers can allow almost completely unrestricted host access.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`privileged:\strue`),
			regexp.MustCompile(`securityContext:`),
			regexp.MustCompile(`(initContainers:|containers:)`),
		},
	}
}
