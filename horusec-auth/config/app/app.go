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
	EnvEnableApplicationAdmin = "HORUSEC_ENABLE_APPLICATION_ADMIN"
	EnvApplicationAdminData   = "HORUSEC_APPLICATION_ADMIN_DATA"
	EnvAuthType               = "HORUSEC_AUTH_TYPE"
	EnvHorusecAPIURL          = "HORUSEC_API_URL"
	EnvDisabledBroker         = "HORUSEC_DISABLED_BROKER"
)

type IConfig interface {
	GetHorusecAPIURL() string
	GetEnableApplicationAdmin() bool
	GetDisabledBroker() bool
	GetApplicationAdminData() (entity *dto.CreateAccount, err error)
	GetAuthType() authEnums.AuthorizationType
}

type Config struct {
	databaseRead SQL.InterfaceRead
}

func NewConfig(databaseRead SQL.InterfaceRead) IConfig {
	return &Config{
		databaseRead: databaseRead,
	}
}

func (c *Config) GetHorusecAPIURL() string {
	return env.GetEnvOrDefault(EnvHorusecAPIURL, "http://localhost:8006")
}

func (c *Config) GetEnableApplicationAdmin() bool {
	return env.GetEnvFromAdminOrDefault(
		c.databaseRead, EnvEnableApplicationAdmin, "false").ToBool()
}

func (c *Config) GetApplicationAdminData() (entity *dto.CreateAccount, err error) {
	defaultApplicationAdmin := &dto.CreateAccount{
		Email:    "horusec-admin@example.com",
		Password: "Devpass0*",
		Username: "horusec-admin",
	}
	createAccountString := env.GetEnvFromAdminOrDefault(
		c.databaseRead, EnvApplicationAdminData, defaultApplicationAdmin.ToString()).ToString()
	return entity, json.Unmarshal([]byte(createAccountString), &entity)
}

func (c *Config) GetAuthType() authEnums.AuthorizationType {
	authTypeString := env.GetEnvFromAdminOrDefault(c.databaseRead, EnvAuthType, authEnums.Horusec.ToString()).ToString()
	authType := authEnums.AuthorizationType(authTypeString)
	if authType.IsInvalid() {
		return authEnums.Unknown
	}
	return authType
}

func (c *Config) GetDisabledBroker() bool {
	return env.GetEnvFromAdminOrDefault(
		c.databaseRead, EnvDisabledBroker, "false").ToBool()
}
