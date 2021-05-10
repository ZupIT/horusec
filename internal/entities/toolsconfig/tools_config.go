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
	Bandit           ToolConfig `json:"bandit"`
	BundlerAudit     ToolConfig `json:"bundleraudit"`
	Brakeman         ToolConfig `json:"brakeman"`
	Flawfinder       ToolConfig `json:"flawfinder"`
	GitLeaks         ToolConfig `json:"gitleaks"`
	GoSec            ToolConfig `json:"gosec"`
	HorusecEngine    ToolConfig `json:"horusecengine"`
	MixAudit         ToolConfig `json:"mixaudit"`
	NpmAudit         ToolConfig `json:"npmaudit"`
	PhpCS            ToolConfig `json:"phpcs"`
	Safety           ToolConfig `json:"safety"`
	SecurityCodeScan ToolConfig `json:"securitycodescan"`
	Semgrep          ToolConfig `json:"semgrep"`
	ShellCheck       ToolConfig `json:"shellcheck"`
	Sobelow          ToolConfig `json:"sobelow"`
	TfSec            ToolConfig `json:"tfsec"`
	YarnAudit        ToolConfig `json:"yarnaudit"`
}

// nolint:funlen // toMap is necessary more 15 lines
func (t *ToolsConfigsStruct) ToMap() MapToolConfig {
	return MapToolConfig{
		tools.Bandit:           t.Bandit,
		tools.BundlerAudit:     t.BundlerAudit,
		tools.Brakeman:         t.Brakeman,
		tools.Flawfinder:       t.Flawfinder,
		tools.GitLeaks:         t.GitLeaks,
		tools.GoSec:            t.GoSec,
		tools.HorusecEngine:    t.HorusecEngine,
		tools.MixAudit:         t.MixAudit,
		tools.NpmAudit:         t.NpmAudit,
		tools.PhpCS:            t.PhpCS,
		tools.Safety:           t.Safety,
		tools.SecurityCodeScan: t.SecurityCodeScan,
		tools.Semgrep:          t.Semgrep,
		tools.ShellCheck:       t.ShellCheck,
		tools.Sobelow:          t.Sobelow,
		tools.TfSec:            t.TfSec,
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
