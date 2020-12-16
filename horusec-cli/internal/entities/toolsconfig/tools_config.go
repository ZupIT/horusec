package toolsconfig

import (
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
)

type ToolConfig struct {
	IsToIgnore bool   `json:"isToIgnore"`
	ImagePath  string `json:"imagePath"`
}

func ParseInterfaceToMapToolsConfig(input interface{}) (output map[tools.Tool]ToolConfig) {
	bytes, err := json.Marshal(input)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToToolsConfig, err, logger.ErrorLevel)
		return NewMapToolConfig()
	}

	err = json.Unmarshal(bytes, &output)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToToolsConfig, err, logger.ErrorLevel)
		return NewMapToolConfig()
	}
	return output
}

//nolint:funlen parse struct is necessary > 15 lines
func NewMapToolConfig() map[tools.Tool]ToolConfig {
	return map[tools.Tool]ToolConfig{
		tools.GoSec:             {IsToIgnore: true, ImagePath: ""},
		tools.SecurityCodeScan:  {IsToIgnore: true, ImagePath: ""},
		tools.Brakeman:          {IsToIgnore: true, ImagePath: ""},
		tools.Safety:            {IsToIgnore: true, ImagePath: ""},
		tools.Bandit:            {IsToIgnore: true, ImagePath: ""},
		tools.NpmAudit:          {IsToIgnore: true, ImagePath: ""},
		tools.YarnAudit:         {IsToIgnore: true, ImagePath: ""},
		tools.HorusecKotlin:     {IsToIgnore: true, ImagePath: ""},
		tools.HorusecJava:       {IsToIgnore: true, ImagePath: ""},
		tools.HorusecLeaks:      {IsToIgnore: true, ImagePath: ""},
		tools.GitLeaks:          {IsToIgnore: true, ImagePath: ""},
		tools.TfSec:             {IsToIgnore: true, ImagePath: ""},
		tools.Semgrep:           {IsToIgnore: true, ImagePath: ""},
		tools.HorusecCsharp:     {IsToIgnore: true, ImagePath: ""},
		tools.HorusecKubernetes: {IsToIgnore: true, ImagePath: ""},
		tools.Eslint:            {IsToIgnore: true, ImagePath: ""},
		tools.HorusecNodejs:     {IsToIgnore: true, ImagePath: ""},
		tools.Flawfinder:        {IsToIgnore: true, ImagePath: ""},
		tools.PhpCS:             {IsToIgnore: true, ImagePath: ""},
	}
}
