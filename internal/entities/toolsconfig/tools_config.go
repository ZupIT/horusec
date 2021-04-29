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
	GoSec            ToolConfig `json:"gosec"`
	SecurityCodeScan ToolConfig `json:"securitycodescan"`
	Brakeman         ToolConfig `json:"brakeman"`
	Safety           ToolConfig `json:"safety"`
	Bandit           ToolConfig `json:"bandit"`
	NpmAudit         ToolConfig `json:"npmaudit"`
	YarnAudit        ToolConfig `json:"yarnaudit"`
	GitLeaks         ToolConfig `json:"gitleaks"`
	TfSec            ToolConfig `json:"tfsec"`
	Semgrep          ToolConfig `json:"semgrep"`
	Eslint           ToolConfig `json:"eslint"`
	Flawfinder       ToolConfig `json:"flawfinder"`
	PhpCS            ToolConfig `json:"phpcs"`
	ShellCheck       ToolConfig `json:"shellcheck"`
}

func (t *ToolsConfigsStruct) ToMap() MapToolConfig {
	return MapToolConfig{
		tools.GoSec:            t.GoSec,
		tools.SecurityCodeScan: t.SecurityCodeScan,
		tools.Brakeman:         t.Brakeman,
		tools.Safety:           t.Safety,
		tools.Bandit:           t.Bandit,
		tools.NpmAudit:         t.NpmAudit,
		tools.YarnAudit:        t.YarnAudit,
		tools.GitLeaks:         t.GitLeaks,
		tools.TfSec:            t.TfSec,
		tools.Semgrep:          t.Semgrep,
		tools.Flawfinder:       t.Flawfinder,
		tools.PhpCS:            t.PhpCS,
		tools.ShellCheck:       t.ShellCheck,
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
