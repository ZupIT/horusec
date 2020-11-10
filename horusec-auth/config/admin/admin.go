package admin

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
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

func getDefaultAccountApplicationAdmin(config *app.Config) *authEntities.Account {
	entity, err := config.GetApplicationAdminData()
	if err != nil {
		logger.LogPanic("Some error occurs when parse Application Admin Data to Account", err)
	}
	pass := entity.Password
	return &authEntities.Account{
		Email:              entity.Email,
		Password:           pass,
		Username:           entity.Username,
		IsConfirmed:        true,
		IsApplicationAdmin: true,
	}
}
