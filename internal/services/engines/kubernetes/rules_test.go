// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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
	"path/filepath"
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	tempDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-KUBERNETES-1",
			Rule:     NewAllowPrivilegeEscalation(),
			Src:      SampleVulnerableHSKUBERNETES1,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-1.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "allowPrivilegeEscalation: true",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-KUBERNETES-1.test"),
						Line:     10,
						Column:   1,
					},
				},
			},
		},
		{
			Name:     "HS-KUBERNETES-2",
			Rule:     NewHostAliases(),
			Src:      SampleVulnerableHSKUBERNETES2,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-2.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "hostAliases:",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-KUBERNETES-2.test"),
						Line:     8,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-KUBERNETES-3",
			Rule:     NewDockerSock(),
			Src:      SampleVulnerableHSKUBERNETES3,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-3.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "path: /var/run/docker.sock",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-KUBERNETES-3.test"),
						Line:     11,
						Column:   12,
					},
				},
			},
		},
		{
			Name:     "HS-KUBERNETES-4",
			Rule:     NewCapabilitySystemAdmin(),
			Src:      SampleVulnerableHSKUBERNETES4,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-4.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "- SYS_ADMIN",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-KUBERNETES-4.test"),
						Line:     14,
						Column:   14,
					},
				},
			},
		},
		{
			Name:     "HS-KUBERNETES-5",
			Rule:     NewPrivilegedContainer(),
			Src:      SampleVulnerableHSKUBERNETES5,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-5.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "privileged: true",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-KUBERNETES-5.test"),
						Line:     12,
						Column:   8,
					},
				},
			},
		},
		{
			Name:     "HS-KUBERNETES-6",
			Rule:     NewSeccompUnconfined(),
			Src:      SampleVulnerableHSKUBERNETES6,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-6.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "seccomp.security.alpha.kubernetes.io/allowedProfileNames: unconfined",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-KUBERNETES-6.test"),
						Line:     6,
						Column:   4,
					},
				},
			},
		},
		{
			Name:     "HS-KUBERNETES-7",
			Rule:     NewHostIPC(),
			Src:      SampleVulnerableHSKUBERNETES7,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-7.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "hostIPC: true",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-KUBERNETES-7.test"),
						Line:     11,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-KUBERNETES-8",
			Rule:     NewHostPID(),
			Src:      SampleVulnerableHSKUBERNETES8,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-8.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "hostPID: true",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-KUBERNETES-8.test"),
						Line:     11,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-KUBERNETES-9",
			Rule:     NewHostNetwork(),
			Src:      SampleVulnerableHSKUBERNETES9,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-9.test"),
			Findings: []engine.Finding{
				{
					CodeSample: "hostNetwork: true",
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-KUBERNETES-9.test"),
						Line:     12,
						Column:   2,
					},
				},
			},
		},
		{
			Name:     "HS-GHACTION-1",
			Rule:     NewGHActionsSensitiveInformationExposureWithEcho(),
			Src:      SampleVulnerableHSGHACTION1,
			Filename: filepath.Join(tempDir, "HS-GHACTION-1.test"),
			Findings: []engine.Finding{
				{
					CodeSample: `run: echo ${{ secrets.TOKEN }}`,
					SourceLocation: engine.Location{
						Filename: filepath.Join(tempDir, "HS-GHACTION-1.test"),
						Line:     14,
						Column:   13,
					},
				},
			},
		},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	tempDir := t.TempDir()
	testcases := []*testutil.RuleTestCase{
		{
			Name:     "HS-KUBERNETES-1",
			Rule:     NewAllowPrivilegeEscalation(),
			Src:      SampleSafeHSKUBERNETES1,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-1.test"),
		},
		{
			Name:     "HS-KUBERNETES-2",
			Rule:     NewHostAliases(),
			Src:      SampleSafeHSKUBERNETES2,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-2.test"),
		},
		{
			Name:     "HS-KUBERNETES-3",
			Rule:     NewDockerSock(),
			Src:      SampleSafeHSKUBERNETES3,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-3.test"),
		},
		{
			Name:     "HS-KUBERNETES-4",
			Rule:     NewCapabilitySystemAdmin(),
			Src:      SampleSafeHSKUBERNETES4,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-4.test"),
		},
		{
			Name:     "HS-KUBERNETES-5",
			Rule:     NewPrivilegedContainer(),
			Src:      SampleSafeHSKUBERNETES5,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-5.test"),
		},
		{
			Name:     "HS-KUBERNETES-6",
			Rule:     NewSeccompUnconfined(),
			Src:      SampleSafeHSKUBERNETES6,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-6.test"),
		},
		{
			Name:     "HS-KUBERNETES-7",
			Rule:     NewHostIPC(),
			Src:      SampleSafeHSKUBERNETES7,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-7.test"),
		},
		{
			Name:     "HS-KUBERNETES-8",
			Rule:     NewHostPID(),
			Src:      SampleSafeHSKUBERNETES8,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-8.test"),
		},
		{
			Name:     "HS-KUBERNETES-9",
			Rule:     NewHostNetwork(),
			Src:      SampleSafeHSKUBERNETES9,
			Filename: filepath.Join(tempDir, "HS-KUBERNETES-9.test"),
		},
		{
			Name:     "HS-GHACTION-1",
			Rule:     NewGHActionsSensitiveInformationExposureWithEcho(),
			Src:      SampleSafeHSGHACTION1,
			Filename: filepath.Join(tempDir, "HS-GHACTION-1.test"),
		},
	}

	testutil.TestSafeCode(t, testcases)
}
