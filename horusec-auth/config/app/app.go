package app

import (
	"encoding/json"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
)

const (
	EnvEnableApplicationAdminEnv = "HORUSEC_ENABLE_APPLICATION_ADMIN"
	EnvApplicationAdminDataEnv   = "HORUSEC_APPLICATION_ADMIN_DATA"
	EnvAuthType                  = "HORUSEC_AUTH_TYPE"
)

type Config struct {
	EnableApplicationAdmin bool
	ApplicationAdminData   string
	AuthType               string
}

func NewConfig() *Config {
	return &Config{
		AuthType:               env.GetEnvOrDefault(EnvAuthType, authEnums.Horusec.ToString()),
		EnableApplicationAdmin: env.GetEnvOrDefaultBool(EnvEnableApplicationAdminEnv, false),
		ApplicationAdminData: env.GetEnvOrDefault(EnvApplicationAdminDataEnv,
			"{\"username\": \"horusec-admin\", \"email\":\"horusec-admin@example.com\", \"password\":\"Devpass0*\"}"),
	}
}

func (a *Config) GetEnableApplicationAdmin() bool {
	return a.EnableApplicationAdmin
}

func (a *Config) GetApplicationAdminData() (entity *accountEntities.CreateAccount, err error) {
	return entity, json.Unmarshal([]byte(a.ApplicationAdminData), &entity)
}

func (a *Config) GetAuthType() string {
	return a.AuthType
}
