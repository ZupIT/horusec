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
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
)

const (
	EnvEnableApplicationAdmin   = "HORUSEC_ENABLE_APPLICATION_ADMIN"
	EnvApplicationAdminData     = "HORUSEC_APPLICATION_ADMIN_DATA"
	EnvAuthType                 = "HORUSEC_AUTH_TYPE"
	EnvHorusecAPIURL            = "HORUSEC_API_URL"
	EnvDisabledBroker           = "HORUSEC_DISABLED_BROKER"
	DefaultApplicationAdminData = "{\"username\": \"horusec-admin\", \"email\":\"horusec-admin@example.com\", \"password\":\"Devpass0*\"}"
)

type Config struct {
	HorusecAPIURL          string
	EnableApplicationAdmin bool
	ApplicationAdminData   string
	AuthType               authEnums.AuthorizationType
	DisabledBroker         bool
}

func NewConfig(databaseRead SQL.InterfaceRead) *Config {
	c := &Config{}
	c.HorusecAPIURL = env.GetEnvOrDefault(EnvHorusecAPIURL, "http://localhost:8006")
	c.AuthType = authEnums.AuthorizationType(
		env.GetEnvFromAdminDatabaseOrDefault(databaseRead, EnvAuthType, authEnums.Horusec.ToString()).ToString())
	c.EnableApplicationAdmin = env.GetEnvFromAdminDatabaseOrDefault(
		databaseRead, EnvEnableApplicationAdmin, "false").ToBool()
	c.ApplicationAdminData = env.GetEnvFromAdminDatabaseOrDefault(
		databaseRead, EnvApplicationAdminData, DefaultApplicationAdminData).ToString()
	c.DisabledBroker = env.GetEnvFromAdminDatabaseOrDefault(
		databaseRead, EnvDisabledBroker, "false").ToBool()
	return c
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
