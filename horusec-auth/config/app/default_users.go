package app

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"strings"
)

func CreateDefaultUser(config *Config, read relational.InterfaceRead, write relational.InterfaceWrite) {
	if config.GetEnableDefaultUser() {
		if config.GetAuthType() != authEnums.Horusec {
			logger.LogWarnWithLevel("{HORUSEC} Is not possible create default user to auth type different of horusec")
		} else {
			rowsAffected, err := createNewUser(read, write, getDefaultAccountUser(config).SetAccountData())
			if err != nil {
				logger.LogPanic("Some error occurs when create Default User.", err)
			}
			if rowsAffected > 0 {
				logger.LogInfo("Default User created with success!")
			} else {
				logger.LogInfo("Default User already exists!")
			}
		}
	}
}

func CreateDefaultApplicationAdmin(config *Config, read relational.InterfaceRead, write relational.InterfaceWrite) {
	if config.GetEnableApplicationAdmin() {
		if config.GetAuthType() != authEnums.Horusec {
			logger.LogWarnWithLevel("{HORUSEC} Is not possible create default user to auth type different of horusec")
		} else {
			rowsAffected, err := createNewUser(read, write, getDefaultAccountApplicationAdmin(config).SetAccountData())
			if err != nil {
				logger.LogPanic("Some error occurs when create Application Admin.", err)
			}
			if rowsAffected > 0 {
				logger.LogInfo("Application Admin created with success!")
			} else {
				logger.LogInfo("Application Admin already exists!")
			}
		}
	}
}

func createNewUser(read relational.InterfaceRead, write relational.InterfaceWrite,
	newUser *authEntities.Account) (rowsAffected int, err error) {
	err = account.NewAccountRepository(read, write).Create(newUser)
	if err != nil {
		if userIsDuplicated(err) {
			return 0, nil
		}
		return 0, err
	}
	return 1, nil
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
