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

package toolsconfig

import (
	"encoding/json"

	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/internal/helpers/messages"
)

type MapToolConfig map[tools.Tool]ToolConfig

type ToolConfig struct {
	IsToIgnore bool `json:"istoignore"`
}

type ToolsConfigsStruct struct {
	Bandit               ToolConfig `json:"bandit"`
	BundlerAudit         ToolConfig `json:"bundleraudit"`
	Brakeman             ToolConfig `json:"brakeman"`
	Checkov              ToolConfig `json:"checkov"`
	Flawfinder           ToolConfig `json:"flawfinder"`
	GitLeaks             ToolConfig `json:"gitleaks"`
	GoSec                ToolConfig `json:"gosec"`
	HorusecEngine        ToolConfig `json:"horusecengine"`
	MixAudit             ToolConfig `json:"mixaudit"`
	NpmAudit             ToolConfig `json:"npmaudit"`
	PhpCS                ToolConfig `json:"phpcs"`
	Safety               ToolConfig `json:"safety"`
	SecurityCodeScan     ToolConfig `json:"securitycodescan"`
	Semgrep              ToolConfig `json:"semgrep"`
	ShellCheck           ToolConfig `json:"shellcheck"`
	Sobelow              ToolConfig `json:"sobelow"`
	TfSec                ToolConfig `json:"tfsec"`
	YarnAudit            ToolConfig `json:"yarnaudit"`
	OwaspDependencyCheck ToolConfig `json:"owaspDependencyCheck"`
	DotnetCli            ToolConfig `json:"dotnetCli"`
	Nancy                ToolConfig `json:"nancy"`
}

// nolint:funlen // toMap is necessary more 15 lines
func (t *ToolsConfigsStruct) ToMap() MapToolConfig {
	return MapToolConfig{
		tools.Bandit:               t.Bandit,
		tools.BundlerAudit:         t.BundlerAudit,
		tools.Brakeman:             t.Brakeman,
		tools.Checkov:              t.Checkov,
		tools.Flawfinder:           t.Flawfinder,
		tools.GitLeaks:             t.GitLeaks,
		tools.GoSec:                t.GoSec,
		tools.HorusecEngine:        t.HorusecEngine,
		tools.MixAudit:             t.MixAudit,
		tools.NpmAudit:             t.NpmAudit,
		tools.PhpCS:                t.PhpCS,
		tools.Safety:               t.Safety,
		tools.SecurityCodeScan:     t.SecurityCodeScan,
		tools.Semgrep:              t.Semgrep,
		tools.ShellCheck:           t.ShellCheck,
		tools.Sobelow:              t.Sobelow,
		tools.TfSec:                t.TfSec,
		tools.YarnAudit:            t.YarnAudit,
		tools.OwaspDependencyCheck: t.OwaspDependencyCheck,
		tools.DotnetCli:            t.DotnetCli,
		tools.Nancy:                t.Nancy,
	}
}

func ParseInterfaceToMapToolsConfig(input interface{}) (output MapToolConfig) {
	outputStruct := ToolsConfigsStruct{}
	bytes, err := json.Marshal(input)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToToolsConfig, err)
		return outputStruct.ToMap()
	}
	err = json.Unmarshal(bytes, &outputStruct)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToToolsConfig, err)
		return outputStruct.ToMap()
	}
	return outputStruct.ToMap()
}
