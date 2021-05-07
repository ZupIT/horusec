package toolsconfig

import (
	"encoding/json"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
)

type MapToolConfig map[tools.Tool]ToolConfig

type ToolConfig struct {
	IsToIgnore bool `json:"istoignore"`
}

type ToolsConfigsStruct struct {
	GoSec             ToolConfig `json:"gosec"`
	SecurityCodeScan  ToolConfig `json:"securitycodescan"`
	Brakeman          ToolConfig `json:"brakeman"`
	Safety            ToolConfig `json:"safety"`
	Bandit            ToolConfig `json:"bandit"`
	NpmAudit          ToolConfig `json:"npmaudit"`
	YarnAudit         ToolConfig `json:"yarnaudit"`
	HorusecKotlin     ToolConfig `json:"horuseckotlin"`
	HorusecJava       ToolConfig `json:"horusecjava"`
	HorusecLeaks      ToolConfig `json:"horusecleaks"`
	HorusecNginx      ToolConfig `json:"horusecnginx"`
	GitLeaks          ToolConfig `json:"gitleaks"`
	TfSec             ToolConfig `json:"tfsec"`
	Semgrep           ToolConfig `json:"semgrep"`
	HorusecCsharp     ToolConfig `json:"horuseccsharp"`
	HorusecKubernetes ToolConfig `json:"horuseckubernetes"`
	Eslint            ToolConfig `json:"eslint"`
	HorusecNodejs     ToolConfig `json:"horusecnodejs"`
	Flawfinder        ToolConfig `json:"flawfinder"`
	PhpCS             ToolConfig `json:"phpcs"`
	HorusecDart       ToolConfig `json:"horusecdart"`
	ShellCheck        ToolConfig `json:"shellcheck"`
}

//nolint:funlen parse struct is necessary > 15 lines
func (t *ToolsConfigsStruct) ToMap() MapToolConfig {
	return MapToolConfig{
		tools.GoSec:             t.GoSec,
		tools.SecurityCodeScan:  t.SecurityCodeScan,
		tools.Brakeman:          t.Brakeman,
		tools.Safety:            t.Safety,
		tools.Bandit:            t.Bandit,
		tools.NpmAudit:          t.NpmAudit,
		tools.YarnAudit:         t.YarnAudit,
		tools.HorusecKotlin:     t.HorusecKotlin,
		tools.HorusecJava:       t.HorusecJava,
		tools.HorusecLeaks:      t.HorusecLeaks,
		tools.GitLeaks:          t.GitLeaks,
		tools.TfSec:             t.TfSec,
		tools.Semgrep:           t.Semgrep,
		tools.HorusecCsharp:     t.HorusecCsharp,
		tools.HorusecKubernetes: t.HorusecKubernetes,
		tools.Eslint:            t.Eslint,
		tools.HorusecNodejs:     t.HorusecNodejs,
		tools.Flawfinder:        t.Flawfinder,
		tools.PhpCS:             t.PhpCS,
		tools.HorusecDart:       t.HorusecDart,
		tools.HorusecNginx:      t.HorusecNginx,
		tools.ShellCheck:        t.ShellCheck,
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
