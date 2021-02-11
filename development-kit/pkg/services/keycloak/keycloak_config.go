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

type KeycloakConfig struct {
	databaseRead SQL.InterfaceRead
}

func NewKeycloakConfig(databaseRead SQL.InterfaceRead) IKeycloakConfig {
	return &KeycloakConfig{
		databaseRead: databaseRead,
	}
}

func (k *KeycloakConfig) getClient() gocloak.GoCloak {
	basePath := env.GetEnvFromAdminOrDefault(k.databaseRead, "HORUSEC_KEYCLOAK_BASE_PATH", "").ToString()
	return gocloak.NewClient(basePath)
}

func (k *KeycloakConfig) getClientID() string {
	return env.GetEnvFromAdminOrDefault(k.databaseRead, "HORUSEC_KEYCLOAK_CLIENT_ID", "").ToString()
}
func (k *KeycloakConfig) getClientSecret() string {
	return env.GetEnvFromAdminOrDefault(k.databaseRead, "HORUSEC_KEYCLOAK_CLIENT_SECRET", "").ToString()
}
func (k *KeycloakConfig) getRealm() string {
	return env.GetEnvFromAdminOrDefault(k.databaseRead, "HORUSEC_KEYCLOAK_REALM", "").ToString()
}
func (k *KeycloakConfig) getOtp() bool {
	return env.GetEnvFromAdminOrDefault(k.databaseRead, "HORUSEC_KEYCLOAK_OTP", "false").ToBool()
}