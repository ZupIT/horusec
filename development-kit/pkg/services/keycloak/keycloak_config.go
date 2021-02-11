package keycloak

import (
	"github.com/Nerzal/gocloak/v7"
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
)

type IKeycloakConfig interface {
	getClient() gocloak.GoCloak
	getClientID() string
	getClientSecret() string
	getRealm() string
	getOtp() bool
}

type Config struct {
	databaseRead SQL.InterfaceRead
}

func NewKeycloakConfig(databaseRead SQL.InterfaceRead) IKeycloakConfig {
	return &Config{
		databaseRead: databaseRead,
	}
}

func (k *Config) getClient() gocloak.GoCloak {
	basePath := env.GetEnvFromAdminOrDefault(k.databaseRead, "HORUSEC_KEYCLOAK_BASE_PATH", "").ToString()
	return gocloak.NewClient(basePath)
}

func (k *Config) getClientID() string {
	return env.GetEnvFromAdminOrDefault(k.databaseRead, "HORUSEC_KEYCLOAK_CLIENT_ID", "").ToString()
}
func (k *Config) getClientSecret() string {
	return env.GetEnvFromAdminOrDefault(k.databaseRead, "HORUSEC_KEYCLOAK_CLIENT_SECRET", "").ToString()
}
func (k *Config) getRealm() string {
	return env.GetEnvFromAdminOrDefault(k.databaseRead, "HORUSEC_KEYCLOAK_REALM", "").ToString()
}
func (k *Config) getOtp() bool {
	return env.GetEnvFromAdminOrDefault(k.databaseRead, "HORUSEC_KEYCLOAK_OTP", "false").ToBool()
}
