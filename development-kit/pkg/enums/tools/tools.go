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

package tools

type Tool string

const (
	GoSec             Tool = "GoSec"
	SecurityCodeScan  Tool = "SecurityCodeScan"
	Brakeman          Tool = "Brakeman"
	Safety            Tool = "Safety"
	Bandit            Tool = "Bandit"
	NpmAudit          Tool = "NpmAudit"
	YarnAudit         Tool = "YarnAudit"
	SpotBugs          Tool = "SpotBugs"
	HorusecKotlin     Tool = "HorusecKotlin"
	HorusecJava       Tool = "HorusecJava"
	HorusecLeaks      Tool = "HorusecLeaks"
	GitLeaks          Tool = "GitLeaks"
	TfSec             Tool = "TfSec"
	Semgrep           Tool = "Semgrep"
	HorusecCsharp     Tool = "HorusecCsharp"
	HorusecKubernetes Tool = "HorusecKubernetes"
)

func (t Tool) ToString() string {
	return string(t)
}
