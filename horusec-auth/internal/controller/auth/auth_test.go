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
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/horusec-auth/internal/services"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewAuthController(t *testing.T) {
	t.Run("should success create a new controller", func(t *testing.T) {
		mockRead := &relational.MockRead{}

		controller := NewAuthController(mockRead)

		assert.NotNil(t, controller)
	})
}

func TestAuthByType(t *testing.T) {
	t.Run("should authenticate with horusec and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return("success", nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{}, authEnums.Horusec)

		assert.NotNil(t, result)
		assert.NoError(t, err)
	})

	t.Run("should authenticate with keycloak and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return("success", nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{}, authEnums.Keycloak)

		assert.NotNil(t, result)
		assert.NoError(t, err)
	})

	//TODO implements
	t.Run("should authenticate with ldap and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return("success", nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{}, authEnums.Ldap)

		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("should return unauthorized error when invalid auth type", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("Authenticate").Return(nil, errors.New("test"))

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthByType(&authEntities.Credentials{}, "test")

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
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthorizeByType(&authEntities.AuthorizationData{}, authEnums.Horusec)

		assert.True(t, result)
		assert.NoError(t, err)
	})

	t.Run("should authenticate with keycloak and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return(true, nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthorizeByType(&authEntities.AuthorizationData{}, authEnums.Keycloak)

		assert.True(t, result)
		assert.NoError(t, err)
	})

	//TODO implements
	t.Run("should authenticate with ldap and return no errors", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return("success", nil)

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthorizeByType(&authEntities.AuthorizationData{}, authEnums.Ldap)

		assert.False(t, result)
		assert.Error(t, err)
	})

	t.Run("should return unauthorized error when invalid auth type", func(t *testing.T) {
		mockService := &services.MockAuthService{}

		mockService.On("IsAuthorized").Return(nil, errors.New("test"))

		controller := Controller{
			horusAuthService:    mockService,
			keycloakAuthService: mockService,
		}

		result, err := controller.AuthorizeByType(&authEntities.AuthorizationData{}, "test")

		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorUnauthorized, err)
		assert.False(t, result)
	})
}
