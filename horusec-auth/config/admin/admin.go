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

package admin

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
)

func CreateApplicationAdmin(config *app.Config, read relational.InterfaceRead, write relational.InterfaceWrite) {
	if config.GetEnableApplicationAdmin() {
		err := account.NewAccountRepository(read, write).Create(getDefaultAccountApplicationAdmin(config).SetAccountData())
		if err != nil {
			if err.Error() != "pq: duplicate key value violates unique constraint \"accounts_email_key\"" {
				logger.LogPanic("Some error occurs when create application admin", err)
			} else {
				logger.LogInfo("Application admin already exists")
			}
		} else {
			logger.LogInfo("Application admin created with success")
		}
	}
}

func getDefaultAccountApplicationAdmin(config *app.Config) *accountEntities.Account {
	entity, err := config.GetApplicationAdminData()
	if err != nil {
		logger.LogPanic("Some error occurs when parse Application Admin Data to Account", err)
	}
	pass := entity.Password
	return &accountEntities.Account{
		Email:              entity.Email,
		Password:           pass,
		Username:           entity.Username,
		IsConfirmed:        true,
		IsApplicationAdmin: true,
	}
}
