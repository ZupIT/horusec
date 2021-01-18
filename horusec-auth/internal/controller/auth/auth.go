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
	"context"
	"fmt"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountDTO "github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	horusecService "github.com/ZupIT/horusec/horusec-auth/internal/services/horusec"
	keycloakService "github.com/ZupIT/horusec/horusec-auth/internal/services/keycloak"
	"github.com/ZupIT/horusec/horusec-auth/internal/services/ldap"
	"github.com/google/uuid"
)

type IController interface {
	AuthByType(credentials *dto.Credentials) (interface{}, error)
	IsAuthorized(_ context.Context, data *authGrpc.IsAuthorizedData) (*authGrpc.IsAuthorizedResponse, error)
	GetAuthConfig(_ context.Context, data *authGrpc.GetAuthConfigData) (*authGrpc.GetAuthConfigResponse, error)
	GetAccountID(_ context.Context, data *authGrpc.GetAccountData) (*authGrpc.GetAccountDataResponse, error)
}

type Controller struct {
	authGrpc.UnimplementedAuthServiceServer
	horusAuthService    services.IAuthService
	keycloakAuthService services.IAuthService
	ldapAuthService     services.IAuthService
	keycloak            keycloak.IService
	appConfig           *app.Config
}

func NewAuthController(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, appConfig *app.Config) *Controller {
	return &Controller{
		appConfig:           appConfig,
		horusAuthService:    horusecService.NewHorusAuthService(postgresRead, postgresWrite),
		ldapAuthService:     ldap.NewService(postgresRead, postgresWrite),
		keycloakAuthService: keycloakService.NewKeycloakAuthService(postgresRead),
		keycloak:            keycloak.NewKeycloakService(),
	}
}

func (c *Controller) AuthByType(credentials *dto.Credentials) (interface{}, error) {
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

func (c *Controller) IsAuthorized(_ context.Context,
	data *authGrpc.IsAuthorizedData) (*authGrpc.IsAuthorizedResponse, error) {
	c.logGrpcRequest("IsAuthorized")
	switch c.getAuthorizationType() {
	case authEnums.Horusec:
		return c.setIsAuthorizedResponse(c.horusAuthService.IsAuthorized(c.parseToAuthorizationData(data)))
	case authEnums.Keycloak:
		return c.setIsAuthorizedResponse(c.keycloakAuthService.IsAuthorized(c.parseToAuthorizationData(data)))
	case authEnums.Ldap:
		return c.setIsAuthorizedResponse(c.ldapAuthService.IsAuthorized(c.parseToAuthorizationData(data)))
	}

	return c.setIsAuthorizedResponse(false, errors.ErrorUnauthorized)
}

func (c *Controller) parseToAuthorizationData(data *authGrpc.IsAuthorizedData) *dto.AuthorizationData {
	companyID, _ := uuid.Parse(data.CompanyID)
	repositoryID, _ := uuid.Parse(data.RepositoryID)

	return &dto.AuthorizationData{
		Token:        data.Token,
		Role:         authEnums.HorusecRoles(data.Role),
		CompanyID:    companyID,
		RepositoryID: repositoryID,
	}
}

func (c *Controller) setIsAuthorizedResponse(isAuthorized bool, err error) (*authGrpc.IsAuthorizedResponse, error) {
	if err != nil {
		logger.LogError(errors.ErrorFailedToVerifyIsAuthorized, err)
		return nil, err
	}

	return &authGrpc.IsAuthorizedResponse{
		IsAuthorized: isAuthorized,
	}, nil
}

func (c *Controller) GetAuthConfig(_ context.Context,
	_ *authGrpc.GetAuthConfigData) (*authGrpc.GetAuthConfigResponse, error) {
	c.logGrpcRequest("GetAuthConfig")
	authType := c.getAuthorizationType()
	if authType == authEnums.Unknown {
		logger.LogError("", errors.ErrorInvalidAuthType)
		return &authGrpc.GetAuthConfigResponse{AuthType: authEnums.Unknown.ToString()}, errors.ErrorInvalidAuthType
	}

	return &authGrpc.GetAuthConfigResponse{
		ApplicationAdminEnable: c.appConfig.EnableApplicationAdmin,
		AuthType:               authType.ToString(),
		DisabledBroker:         c.appConfig.DisabledBroker,
	}, nil
}

func (c *Controller) getAuthorizationType() authEnums.AuthorizationType {
	return c.appConfig.GetAuthType()
}

func (c *Controller) GetAccountID(_ context.Context,
	data *authGrpc.GetAccountData) (*authGrpc.GetAccountDataResponse, error) {
	c.logGrpcRequest("GetAccountID")
	switch c.getAuthorizationType() {
	case authEnums.Horusec:
		return c.setGetAccountIDResponse(jwt.GetAccountIDByJWTToken(data.Token))
	case authEnums.Keycloak:
		return c.setGetAccountIDResponse(c.keycloak.GetAccountIDByJWTToken(data.Token))
	case authEnums.Ldap:
		return c.setGetAccountIDResponseLdap(jwt.DecodeToken(data.Token))
	}

	return c.setGetAccountIDResponse(uuid.Nil, errors.ErrorUnauthorized)
}

func (c *Controller) setGetAccountIDResponse(accountID uuid.UUID, err error) (*authGrpc.GetAccountDataResponse, error) {
	if err != nil {
		logger.LogError(errors.ErrorFailedToGetAccountID, err)
		return &authGrpc.GetAccountDataResponse{}, err
	}

	return &authGrpc.GetAccountDataResponse{
		AccountID: accountID.String(),
	}, nil
}

func (c *Controller) setGetAccountIDResponseLdap(claimsJTW *accountDTO.ClaimsJWT,
	err error) (*authGrpc.GetAccountDataResponse, error) {
	if err != nil {
		logger.LogError(errors.ErrorFailedToGetAccountID, err)
		return &authGrpc.GetAccountDataResponse{}, err
	}

	return &authGrpc.GetAccountDataResponse{
		AccountID:   claimsJTW.Subject,
		Permissions: claimsJTW.Permissions,
	}, nil
}

func (c *Controller) logGrpcRequest(method string) {
	logger.LogInfo(fmt.Sprintf("{AUTH_GRPC} Received request for: %s", method))
}
