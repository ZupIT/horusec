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

package keycloak

import (
	"errors"
	"github.com/Nerzal/gocloak/v7"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewKeycloakAuthService(t *testing.T) {
	dbRead := &relational.MockRead{}
	k := NewKeycloakAuthService(dbRead)
	assert.NotEmpty(t, k)
}

func TestService_Authenticate(t *testing.T) {
	t.Run("Should run authentication without error", func(t *testing.T) {
		mock := &keycloak.Mock{}
		mock.On("LoginOtp").Return(&gocloak.JWT{
			AccessToken:      "access_token",
			IDToken:          uuid.New().String(),
			ExpiresIn:        15,
			RefreshExpiresIn: 15,
			RefreshToken:     "refresh_token",
			TokenType:        "unique",
		}, nil)
		k := &Service{mock}
		content, err := k.Authenticate(&authEntities.Credentials{
			Username: "admin",
			Password: "admin",
		})
		assert.NoError(t, err)
		assert.NotEmpty(t, content)
	})
	t.Run("Should run authentication with error", func(t *testing.T) {
		mock := &keycloak.Mock{}
		mock.On("LoginOtp").Return(&gocloak.JWT{}, errors.New("unexpected error"))
		k := &Service{mock}
		content, err := k.Authenticate(&authEntities.Credentials{
			Username: "admin",
			Password: "admin",
		})
		assert.Error(t, err)
		assert.Empty(t, content)
	})
}

func TestService_IsAuthorized(t *testing.T) {
	t.Run("Should run is_authorized without error and return true", func(t *testing.T) {
		mock := &keycloak.Mock{}
		mock.On("IsActiveToken").Return(true, nil)
		k := &Service{mock}
		isValid, err := k.IsAuthorized(&authEntities.AuthorizationData{
			Token: "Access token",
			Role:  "",
		})
		assert.NoError(t, err)
		assert.True(t, isValid)
	})
	t.Run("Should run is_authorized without error and return false", func(t *testing.T) {
		mock := &keycloak.Mock{}
		mock.On("IsActiveToken").Return(false, nil)
		k := &Service{mock}
		isValid, err := k.IsAuthorized(&authEntities.AuthorizationData{
			Token: "Access token",
			Role:  "",
		})
		assert.NoError(t, err)
		assert.False(t, isValid)
	})
	t.Run("Should run is_authorized with error", func(t *testing.T) {
		mock := &keycloak.Mock{}
		mock.On("IsActiveToken").Return(false, errors.New("unexpected error"))
		k := &Service{mock}
		isValid, err := k.IsAuthorized(&authEntities.AuthorizationData{
			Token: "Access token",
			Role:  "",
		})
		assert.Error(t, err)
		assert.False(t, isValid)
	})
}
