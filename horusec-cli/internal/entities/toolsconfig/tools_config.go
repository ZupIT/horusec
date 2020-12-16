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

func ParseInterfaceToMapToolsConfig(input interface{}) (output map[string]ToolConfig) {
	bytes, err := json.Marshal(input)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToToolsConfig, err, logger.ErrorLevel)
		return MapToolsConfig()
	}

	err = json.Unmarshal(bytes, &output)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToToolsConfig, err, logger.ErrorLevel)
		return MapToolsConfig()
	}
	return output
}

//nolint:funlen parse struct is necessary > 15 lines
func MapToolsConfig() map[string]ToolConfig {
	return map[string]ToolConfig{
		tools.GoSec.ToLowerCamel():             {IsToIgnore: true, ImagePath: ""},
		tools.SecurityCodeScan.ToLowerCamel():  {IsToIgnore: true, ImagePath: ""},
		tools.Brakeman.ToLowerCamel():          {IsToIgnore: true, ImagePath: ""},
		tools.Safety.ToLowerCamel():            {IsToIgnore: true, ImagePath: ""},
		tools.Bandit.ToLowerCamel():            {IsToIgnore: true, ImagePath: ""},
		tools.NpmAudit.ToLowerCamel():          {IsToIgnore: true, ImagePath: ""},
		tools.YarnAudit.ToLowerCamel():         {IsToIgnore: true, ImagePath: ""},
		tools.HorusecKotlin.ToLowerCamel():     {IsToIgnore: true, ImagePath: ""},
		tools.HorusecJava.ToLowerCamel():       {IsToIgnore: true, ImagePath: ""},
		tools.HorusecLeaks.ToLowerCamel():      {IsToIgnore: true, ImagePath: ""},
		tools.GitLeaks.ToLowerCamel():          {IsToIgnore: true, ImagePath: ""},
		tools.TfSec.ToLowerCamel():             {IsToIgnore: true, ImagePath: ""},
		tools.Semgrep.ToLowerCamel():           {IsToIgnore: true, ImagePath: ""},
		tools.HorusecCsharp.ToLowerCamel():     {IsToIgnore: true, ImagePath: ""},
		tools.HorusecKubernetes.ToLowerCamel(): {IsToIgnore: true, ImagePath: ""},
		tools.Eslint.ToLowerCamel():            {IsToIgnore: true, ImagePath: ""},
		tools.HorusecNodejs.ToLowerCamel():     {IsToIgnore: true, ImagePath: ""},
		tools.Flawfinder.ToLowerCamel():        {IsToIgnore: true, ImagePath: ""},
		tools.PhpCS.ToLowerCamel():             {IsToIgnore: true, ImagePath: ""},
	}
}
