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
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	keycloakService "github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestNewAuthController(t *testing.T) {
	t.Run("should success create a new controller", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		appConfig := &app.Config{}

		controller := NewAuthController(mockRead, appConfig)

		assert.NotNil(t, controller)
	})
}

func TestAuthByType(t *testing.T) {
	t.Run("should authenticate with horusec and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return("success", nil)

		controller := Controller{
			appConfig:           &app.Config{AuthType: authEnums.Horusec.ToString()},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{})

		assert.NotNil(t, result)
		assert.NoError(t, err)
	})

	t.Run("should authenticate with keycloak and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return("success", nil)

		controller := Controller{
			appConfig:           &app.Config{AuthType: authEnums.Keycloak.ToString()},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{})

		assert.NotNil(t, result)
		assert.NoError(t, err)
	})

	//TODO implements
	t.Run("should authenticate with ldap and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return("success", nil)

		controller := Controller{
			appConfig:           &app.Config{AuthType: authEnums.Ldap.ToString()},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{})

		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("should return unauthorized error when invalid auth type", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return(nil, errors.New("test"))

		controller := Controller{
			appConfig:           &app.Config{AuthType: "test"},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{})

		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorUnauthorized, err)
		assert.Nil(t, result)
	})
}

func TestAuthorizeByType(t *testing.T) {
	t.Run("should authenticate with horusec and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return(true, nil)

		controller := Controller{
			appConfig:           &app.Config{AuthType: authEnums.Horusec.ToString()},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.IsAuthorized(nil, &authGrpc.IsAuthorizedData{
			Token:        "test",
			Role:         "test",
			CompanyID:    "test",
			RepositoryID: "test",
		})

		assert.NoError(t, err)
		assert.True(t, result.GetIsAuthorized())
	})

	t.Run("should authenticate with keycloak and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return(true, nil)

		controller := Controller{
			appConfig:           &app.Config{AuthType: authEnums.Keycloak.ToString()},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.IsAuthorized(nil, &authGrpc.IsAuthorizedData{
			Token:        "test",
			Role:         "test",
			CompanyID:    "test",
			RepositoryID: "test",
		})

		assert.NoError(t, err)
		assert.True(t, result.GetIsAuthorized())
	})

	//TODO implements
	t.Run("should authenticate with ldap and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return("success", nil)

		controller := Controller{
			appConfig:           &app.Config{AuthType: authEnums.Ldap.ToString()},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.IsAuthorized(nil, &authGrpc.IsAuthorizedData{
			Token:        "test",
			Role:         "test",
			CompanyID:    "test",
			RepositoryID: "test",
		})

		assert.Error(t, err)
		assert.False(t, result.GetIsAuthorized())
	})

	t.Run("should return unauthorized error when invalid auth type", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", "test")

		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return(nil, errors.New("test"))

		controller := Controller{
			appConfig:           &app.Config{AuthType: "test"},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.IsAuthorized(nil, &authGrpc.IsAuthorizedData{
			Token:        "test",
			Role:         "test",
			CompanyID:    "test",
			RepositoryID: "test",
		})

		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorUnauthorized, err)
		assert.False(t, result.GetIsAuthorized())
	})
}

func TestController_GetAuthTypes(t *testing.T) {
	t.Run("Should return default authentication type", func(t *testing.T) {
		mockService := &services.MockAuthService{}
		controller := Controller{
			appConfig:           &app.Config{AuthType: authEnums.Horusec.ToString()},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}
		authType, err := controller.GetAuthConfig(nil, nil)
		assert.NoError(t, err)
		assert.Equal(t, authEnums.Horusec.ToString(), authType.GetAuthType())
	})

	t.Run("Should return error when invalid type", func(t *testing.T) {
		mockService := &services.MockAuthService{}
		controller := Controller{
			appConfig:           &app.Config{AuthType: "test"},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}
		authType, err := controller.GetAuthConfig(nil, nil)
		assert.Error(t, err)
		assert.Equal(t, authEnums.Unknown.ToString(), authType.GetAuthType())
	})
}

func TestGetAccountIDByAuthType(t *testing.T) {
	t.Run("should return account id when horusec", func(t *testing.T) {
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Email:     "test@test.com",
			Username:  "test",
		}

		token, _, _ := jwt.CreateToken(account, nil)

		mockService := &services.MockAuthService{}

		controller := Controller{
			appConfig:           &app.Config{AuthType: authEnums.Horusec.ToString()},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		response, err := controller.GetAccountID(nil, &authGrpc.GetAccountIDData{Token: token})

		assert.NoError(t, err)
		assert.NotEmpty(t, response.GetAccountID())
	})

	t.Run("should return account id when keycloak", func(t *testing.T) {
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Email:     "test@test.com",
			Username:  "test",
		}

		token, _, _ := jwt.CreateToken(account, nil)

		keycloakMock := &keycloakService.Mock{}
		mockService := &services.MockAuthService{}

		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		controller := Controller{
			appConfig:           &app.Config{AuthType: authEnums.Keycloak.ToString()},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
			keycloak:            keycloakMock,
		}

		response, err := controller.GetAccountID(nil, &authGrpc.GetAccountIDData{Token: token})

		assert.NoError(t, err)
		assert.NotEmpty(t, response.GetAccountID())
	})

	t.Run("should return account id when horusec", func(t *testing.T) {
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Email:     "test@test.com",
			Username:  "test",
		}

		token, _, _ := jwt.CreateToken(account, nil)

		mockService := &services.MockAuthService{}

		controller := Controller{
			appConfig:           &app.Config{AuthType: authEnums.Ldap.ToString()},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		response, err := controller.GetAccountID(nil, &authGrpc.GetAccountIDData{Token: token})

		assert.NoError(t, err)
		assert.NotEmpty(t, response.GetAccountID())
	})

	t.Run("should return error when invalid auth type", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		controller := Controller{
			appConfig:           &app.Config{AuthType: "test"},
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		response, err := controller.GetAccountID(nil, &authGrpc.GetAccountIDData{Token: "test"})

		assert.Error(t, err)
		assert.Empty(t, response.GetAccountID())
	})
}
