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
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	horusecService "github.com/ZupIT/horusec/horusec-auth/internal/services/horusec"
	"github.com/ZupIT/horusec/horusec-auth/internal/services/keycloak"
)

type IController interface {
	AuthByType(credentials *authEntities.Credentials, authorizationType authEnums.AuthorizationType) (interface{}, error)
	AuthorizeByType(authorizationData *authEntities.AuthorizationData,
		authorizationType authEnums.AuthorizationType) (bool, error)
}

type Controller struct {
	horusAuthService    services.IAuthService
	keycloakAuthService services.IAuthService
}

func NewAuthController(postgresRead relational.InterfaceRead) IController {
	return &Controller{
		horusAuthService:    horusecService.NewHorusAuthService(postgresRead),
		keycloakAuthService: keycloak.NewKeycloakAuthService(postgresRead),
	}
}

func (c *Controller) AuthByType(credentials *authEntities.Credentials,
	authorizationType authEnums.AuthorizationType) (interface{}, error) {
	switch authorizationType {
	case authEnums.Horusec:
		return c.horusAuthService.Authenticate(credentials)
	case authEnums.Keycloak:
		return c.keycloakAuthService.Authenticate(credentials)
	case authEnums.Ldap:
		return nil, errors.ErrorUnauthorized
	}

	return nil, errors.ErrorUnauthorized
}

func (c *Controller) AuthorizeByType(authorizationData *authEntities.AuthorizationData,
	authorizationType authEnums.AuthorizationType) (bool, error) {
	switch authorizationType {
	case authEnums.Horusec:
		return c.horusAuthService.IsAuthorized(authorizationData)
	case authEnums.Keycloak:
		return c.keycloakAuthService.IsAuthorized(authorizationData)
	case authEnums.Ldap:
		return false, errors.ErrorUnauthorized
	}

	return false, errors.ErrorUnauthorized
}
