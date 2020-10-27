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
	"os"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	keycloakService "github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthController(t *testing.T) {
	t.Run("should success create a new controller", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		controller := NewAuthController(mockRead, mockWrite)

		assert.NotNil(t, controller)
	})
}

func TestAuthByType(t *testing.T) {
	t.Run("should authenticate with horusec and return no errors", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", authEnums.Horusec.ToString())
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return("success", nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{})

		assert.NotNil(t, result)
		assert.NoError(t, err)
	})

	t.Run("should authenticate with keycloak and return no errors", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", authEnums.Keycloak.ToString())
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return("success", nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{})

		assert.NotNil(t, result)
		assert.NoError(t, err)
	})

	//TODO implements
	t.Run("should authenticate with ldap and return no errors", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", authEnums.Ldap.ToString())
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return("success", nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{})

		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("should return unauthorized error when invalid auth type", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", "test")
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return(nil, errors.New("test"))

		controller := Controller{
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
		_ = os.Setenv("HORUSEC_AUTH_TYPE", authEnums.Horusec.ToString())

		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return(true, nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthorizeByType(&authEntities.AuthorizationData{})

		assert.True(t, result)
		assert.NoError(t, err)
	})

	t.Run("should authenticate with keycloak and return no errors", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", authEnums.Keycloak.ToString())

		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return(true, nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthorizeByType(&authEntities.AuthorizationData{})

		assert.True(t, result)
		assert.NoError(t, err)
	})

	//TODO implements
	t.Run("should authenticate with ldap and return no errors", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", authEnums.Ldap.ToString())

		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return("success", nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthorizeByType(&authEntities.AuthorizationData{})

		assert.False(t, result)
		assert.Error(t, err)
	})

	t.Run("should return unauthorized error when invalid auth type", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", "test")

		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return(nil, errors.New("test"))

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthorizeByType(&authEntities.AuthorizationData{})

		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorUnauthorized, err)
		assert.False(t, result)
	})
}

func TestController_GetAuthTypes(t *testing.T) {
	t.Run("Should return default authentication type", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", authEnums.Horusec.ToString())

		mockService := &services.MockAuthService{}
		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}
		authType, err := controller.GetAuthType()
		assert.NoError(t, err)
		assert.Equal(t, authEnums.Horusec, authType)
	})
}

func TestGetAccountIDByAuthType(t *testing.T) {
	t.Run("should return account id when horusec", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", authEnums.Horusec.ToString())
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Email:     "test@test.com",
			Username:  "test",
		}

		token, _, _ := jwt.CreateToken(account, nil)

		mockService := &services.MockAuthService{}

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		accountID, err := controller.GetAccountIDByAuthType(token)

		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, accountID)
	})

	t.Run("should return account id when keycloak", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", authEnums.Keycloak.ToString())
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
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
			keycloak:            keycloakMock,
		}

		accountID, err := controller.GetAccountIDByAuthType(token)

		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, accountID)
	})

	t.Run("should return account id when horusec", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", authEnums.Ldap.ToString())
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Email:     "test@test.com",
			Username:  "test",
		}

		token, _, _ := jwt.CreateToken(account, nil)

		mockService := &services.MockAuthService{}

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		accountID, err := controller.GetAccountIDByAuthType(token)

		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, accountID)
	})

	t.Run("should return account id when horusec", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_AUTH_TYPE", "test")

		mockService := &services.MockAuthService{}

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		accountID, err := controller.GetAccountIDByAuthType("test")

		assert.Error(t, err)
		assert.Equal(t, uuid.Nil, accountID)
	})
}
