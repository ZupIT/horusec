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

package auth

import (
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
)

type ConfigAuth struct {
	ApplicationAdminEnable          bool                   `json:"applicationAdminEnable"`
	DisabledBroker                  bool                   `json:"disabledBroker"`
	AuthType                        auth.AuthorizationType `json:"authType"`
	ReactAppKeycloakClientID        string                 `json:"reactAppKeycloakClientID"`
	ReactAppKeycloakRealm           string                 `json:"reactAppKeycloakRealm"`
	ReactAppKeycloakBasePath        string                 `json:"reactAppKeycloakBasePath"`
	ReactAppHorusecEndpointAPI      string                 `json:"reactAppHorusecEndpointApi"`
	ReactAppHorusecEndpointAnalytic string                 `json:"reactAppHorusecEndpointAnalytic"`
	ReactAppHorusecEndpointAccount  string                 `json:"reactAppHorusecEndpointAccount"`
	ReactAppHorusecEndpointAuth     string                 `json:"reactAppHorusecEndpointAuth"`
	ReactAppHorusecManagerPath      string                 `json:"reactAppHorusecManagerPath"`
}

func ParseInterfaceToConfigAuth(content interface{}) (configAuth ConfigAuth, err error) {
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return ConfigAuth{}, err
	}
	return configAuth, json.Unmarshal(contentBytes, &configAuth)
}
