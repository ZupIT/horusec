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
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewAllowPrivilegeEscalation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1e0be755-5333-4a74-ade4-d23a95d58b54",
			Name:        "Allow Privilege Escalation",
			Description: "Privileged containers share namespaces with the host system, eschew cgroup restrictions, and do not offer any security. They should be used exclusively as a bundling and distribution mechanism for the code in the container, and not for isolation.",
			Severity:    severities.Medium.ToString(),
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

func NewHostAliases() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fc601f5a-0dd9-472f-9476-24f12ef8e990",
			Name:        "Host Aliases",
			Description: "Managing /etc/hosts aliases can prevent the container from modifying the file after a pod's containers have already been started. DNS should be managed by the orchestrator.",
			Severity:    severities.Low.ToString(),
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

func NewDockerSock() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "89b452df-dfbd-487c-a6c6-9e002aac0823",
			Name:        "Docker Sock",
			Description: "Mounting the docker.socket leaks information about other containers and can allow container breakout.",
			Severity:    severities.Medium.ToString(),
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

func NewCapabilitySystemAdmin() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3e68d755-e860-49db-84b4-65f323edb1f1",
			Name:        "Capability System Admin",
			Description: "CAP_SYS_ADMIN is the most privileged capability and should always be avoided.",
			Severity:    severities.Critical.ToString(),
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

func NewPrivilegedContainer() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6deb1d82-7579-4e1b-9f1e-ed287e0eaccb",
			Name:        "Privileged Container",
			Description: "Privileged containers can allow almost completely unrestricted host access.",
			Severity:    severities.High.ToString(),
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

func NewSeccompUnconfined() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9b26b361-7a92-465a-ae77-1c7122266823",
			Name:        "Seccomp Unconfined",
			Description: "Unconfined Seccomp profiles have full system call access.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`seccomp\.security\.alpha\.kubernetes\.io/[a-zA-Z-.]+: unconfined`),
			regexp.MustCompile(`[\[ ]seccomp\.security\.alpha\.kubernetes\.io/[a-zA-Z-.]+:unconfined[\] ]`),
		},
	}
}

func NewHostIPC() text.TextRule {
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

func NewHostPID() text.TextRule {
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

func NewHostNetwork() text.TextRule {
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
