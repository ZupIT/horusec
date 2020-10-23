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
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
)

const (
	DisableEmailServiceEnv    = "HORUSEC_ACCOUNT_DISABLE_EMAIL_SERVICE"
	EnableApplicationAdminEnv = "HORUSEC_ENABLE_APPLICATION_ADMIN"
	ApplicationAdminDataEnv   = "HORUSEC_APPLICATION_ADMIN_DATA"
)

type Config struct {
	DisableEmailService    bool
	EnableApplicationAdmin bool
	ApplicationAdminData   string
}

type IAppConfig interface {
	IsEmailServiceDisabled() bool
	IsEnableApplicationAdmin() bool
	GetApplicationAdminData() (entity *accountEntities.CreateAccount, err error)
}

func SetupApp() IAppConfig {
	return &Config{
		DisableEmailService:    env.GetEnvOrDefaultBool(DisableEmailServiceEnv, false),
		EnableApplicationAdmin: env.GetEnvOrDefaultBool(EnableApplicationAdminEnv, false),
		ApplicationAdminData: env.GetEnvOrDefault(
			ApplicationAdminDataEnv,
			"{\"username\": \"horusec-admin\", \"email\":\"horusec-admin@example.com\", \"password\":\"Devpass0*\"}"),
	}
}

func (a *Config) IsEmailServiceDisabled() bool {
	return a.DisableEmailService
}

func (a *Config) IsEnableApplicationAdmin() bool {
	return a.EnableApplicationAdmin
}

func (a *Config) GetApplicationAdminData() (entity *accountEntities.CreateAccount, err error) {
	return entity, json.Unmarshal([]byte(a.ApplicationAdminData), &entity)
}
