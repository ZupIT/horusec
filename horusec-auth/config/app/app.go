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

package app

import (
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
)

const (
	EnvEnableApplicationAdminEnv = "HORUSEC_ENABLE_APPLICATION_ADMIN"
	EnvApplicationAdminDataEnv   = "HORUSEC_APPLICATION_ADMIN_DATA"
	EnvAuthType                  = "HORUSEC_AUTH_TYPE"
	EnvHorusecAPIURL             = "HORUSEC_API_URL"
	DisabledBrokerEnv            = "HORUSEC_DISABLED_BROKER"
)

type Config struct {
	HorusecAPIURL             string
	EnableApplicationAdmin bool
	ApplicationAdminData   string
	AuthType               authEnums.AuthorizationType
	DisabledBroker         bool
}

func NewConfig() *Config {
	return &Config{
		HorusecAPIURL:          env.GetEnvOrDefault(EnvHorusecAPIURL, "http://localhost:8003"),
		AuthType:               authEnums.AuthorizationType(env.GetEnvOrDefault(EnvAuthType, authEnums.Horusec.ToString())),
		EnableApplicationAdmin: env.GetEnvOrDefaultBool(EnvEnableApplicationAdminEnv, true),
		ApplicationAdminData: env.GetEnvOrDefault(EnvApplicationAdminDataEnv,
			"{\"username\": \"horusec-admin\", \"email\":\"horusec-admin@example.com\", \"password\":\"Devpass0*\"}"),
		DisabledBroker: env.GetEnvOrDefaultBool(DisabledBrokerEnv, false),
	}
}

func (a *Config) GetEnableApplicationAdmin() bool {
	return a.EnableApplicationAdmin
}

func (a *Config) GetApplicationAdminData() (entity *dto.CreateAccount, err error) {
	return entity, json.Unmarshal([]byte(a.ApplicationAdminData), &entity)
}

func (a *Config) GetAuthType() authEnums.AuthorizationType {
	return a.AuthType
}

func (a *Config) GetHorusecAPIURL() string {
	return a.HorusecAPIURL
}

func (a *Config) IsDisabledBroker() bool {
	return a.DisabledBroker
}
