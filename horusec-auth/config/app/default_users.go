package app

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"strings"
)

func CreateDefaultUser(config *Config, read relational.InterfaceRead, write relational.InterfaceWrite) {
	if config.GetEnableDefaultUser() {
		err := account.NewAccountRepository(read, write).Create(getDefaultAccountUser(config).SetAccountData())
		if err != nil {
			if userIsDuplicated(err) {
				logger.LogInfo("Default user already exists")
			} else {
				logger.LogPanic("Some error occurs when create application admin", err)
			}
		} else {
			logger.LogInfo("Default user created with success")
		}
	}
}

func CreateDefaultApplicationAdmin(config *Config, read relational.InterfaceRead, write relational.InterfaceWrite) {
	if config.GetEnableApplicationAdmin() {
		err := account.NewAccountRepository(read, write).Create(getDefaultAccountApplicationAdmin(config).SetAccountData())
		if err != nil {
			if userIsDuplicated(err) {
				logger.LogInfo("Application admin already exists")
			} else {
				logger.LogPanic("Some error occurs when create application admin", err)
			}
		} else {
			logger.LogInfo("Application admin created with success")
		}
	}
}

func userIsDuplicated(err error) bool {
	const msgAlreadyExists = "duplicate key value violates unique constraint \"accounts_email_key\""
	if err == nil {
		return false
	}
	errorString := strings.ToLower(err.Error())
	return strings.Contains(errorString, msgAlreadyExists)
}

func getDefaultAccountUser(config *Config) *authEntities.Account {
	entity, err := config.GetDefaultUserData()
	if err != nil {
		logger.LogPanic("Some error occurs when parse Default user Data to Account", err)
	}
	pass := entity.Password
	return &authEntities.Account{
		Email:              entity.Email,
		Password:           pass,
		Username:           entity.Username,
		IsConfirmed:        true,
		IsApplicationAdmin: false,
	}
}

func getDefaultAccountApplicationAdmin(config *Config) *authEntities.Account {
	entity, err := config.GetApplicationAdminData()
	if err != nil {
		logger.LogPanic("{HORUSEC} Some error occurs when parse Application Admin Data to Account", err)
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
