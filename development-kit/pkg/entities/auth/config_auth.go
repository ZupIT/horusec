package auth

import (
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
)

type ConfigAuth struct {
	ApplicationAdminEnable bool `json:"applicationAdminEnable"`
	AuthType auth.AuthorizationType `json:"authType"`
}

func ParseContentToConfigAuth(content interface{}) (configAuth ConfigAuth, err error) {
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return ConfigAuth{}, err
	}
	return configAuth, json.Unmarshal(contentBytes, &configAuth)
}