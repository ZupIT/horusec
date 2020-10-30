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

package auth

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	horusecService "github.com/ZupIT/horusec/horusec-auth/internal/services/horusec"
	keycloakService "github.com/ZupIT/horusec/horusec-auth/internal/services/keycloak"
	"github.com/ZupIT/horusec/horusec-auth/internal/services/ldap"
	"github.com/google/uuid"
)

type IController interface {
	AuthByType(credentials *authEntities.Credentials) (interface{}, error)
	AuthorizeByType(authorizationData *authEntities.AuthorizationData) (bool, error)
	GetAuthType() (authEnums.AuthorizationType, error)
	GetAccountIDByAuthType(token string) (uuid.UUID, error)
}

type Controller struct {
	horusAuthService    services.IAuthService
	keycloakAuthService services.IAuthService
	ldapAuthService     services.IAuthService
	keycloak            keycloak.IService
	appConfig           *app.Config
}

func NewAuthController(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, appConfig *app.Config) IController {
	return &Controller{
		appConfig:           appConfig,
		horusAuthService:    horusecService.NewHorusAuthService(postgresRead, postgresWrite),
		ldapAuthService:     ldap.NewService(postgresRead, postgresWrite),
		keycloakAuthService: keycloakService.NewKeycloakAuthService(postgresRead),
		keycloak:            keycloak.NewKeycloakService(),
	}
}

func (c *Controller) AuthByType(credentials *authEntities.Credentials) (interface{}, error) {
	switch c.getAuthorizationType() {
	case authEnums.Horusec:
		return c.horusAuthService.Authenticate(credentials)
	case authEnums.Keycloak:
		return c.keycloakAuthService.Authenticate(credentials)
	case authEnums.Ldap:
		return c.ldapAuthService.Authenticate(credentials)
	}

	return nil, errors.ErrorUnauthorized
}

func (c *Controller) AuthorizeByType(authorizationData *authEntities.AuthorizationData) (bool, error) {
	switch c.getAuthorizationType() {
	case authEnums.Horusec:
		return c.horusAuthService.IsAuthorized(authorizationData)
	case authEnums.Keycloak:
		return c.keycloakAuthService.IsAuthorized(authorizationData)
	case authEnums.Ldap:
		return c.ldapAuthService.IsAuthorized(authorizationData)
	}

	return false, errors.ErrorUnauthorized
}

func (c *Controller) GetAuthType() (authorizationType authEnums.AuthorizationType, err error) {
	authType := c.getAuthorizationType()
	if authType != authEnums.Unknown {
		return authType, nil
	}

	return "", errors.ErrorInvalidAuthType
}

func (c *Controller) getAuthorizationType() authEnums.AuthorizationType {
	return c.appConfig.GetAuthType()
}

func (c *Controller) GetAccountIDByAuthType(token string) (uuid.UUID, error) {
	switch c.getAuthorizationType() {
	case authEnums.Horusec:
		return jwt.GetAccountIDByJWTToken(token)
	case authEnums.Keycloak:
		return c.keycloak.GetAccountIDByJWTToken(token)
	case authEnums.Ldap:
		return jwt.GetAccountIDByJWTToken(token)
	}

	return uuid.Nil, errors.ErrorUnauthorized
}
