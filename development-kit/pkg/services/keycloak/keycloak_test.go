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
	"context"
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"testing"

	"github.com/Nerzal/gocloak/v7"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type GoCloakMock struct {
	mock.Mock
	gocloak.GoCloak
}

func (m *GoCloakMock) LoginOtp(ctx context.Context, clientID, clientSecret, realm, username, password, totp string) (*gocloak.JWT, error) {
	args := m.MethodCalled("LoginOtp")
	return args.Get(0).(*gocloak.JWT), mockUtils.ReturnNilOrError(args, 1)
}
func (m *GoCloakMock) RetrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (*gocloak.RetrospecTokenResult, error) {
	args := m.MethodCalled("RetrospectToken")
	return args.Get(0).(*gocloak.RetrospecTokenResult), mockUtils.ReturnNilOrError(args, 1)
}
func (m *GoCloakMock) GetUserInfo(ctx context.Context, accessToken, realm string) (*gocloak.UserInfo, error) {
	args := m.MethodCalled("GetUserInfo")
	return args.Get(0).(*gocloak.UserInfo), mockUtils.ReturnNilOrError(args, 1)
}

func TestNewKeycloakService(t *testing.T) {
	t.Run("Should return default type service keycloak", func(t *testing.T) {
		assert.IsType(t, NewKeycloakService(env.GlobalAdminReadMock(0, nil, nil)), &Service{})
	})
}

func TestService_LoginOtp(t *testing.T) {
	t.Run("Should login with success in keycloak", func(t *testing.T) {
		goCloakMock := &GoCloakMock{}
		goCloakMock.On("LoginOtp").Return(&gocloak.JWT{
			AccessToken:      "access_token",
			IDToken:          uuid.New().String(),
			ExpiresIn:        15,
			RefreshExpiresIn: 15,
			RefreshToken:     "refresh_token",
			TokenType:        "unique",
		}, nil)
		keycloakConfigMock := &Mock{}
		keycloakConfigMock.On("getClient").Return(goCloakMock)
		keycloakConfigMock.On("getClientID").Return("")
		keycloakConfigMock.On("getClientSecret").Return("")
		keycloakConfigMock.On("getRealm").Return("")
		keycloakConfigMock.On("getOtp").Return(false)
		service := &Service{
			ctx:          context.Background(),
			config:       keycloakConfigMock,
		}
		resp, err := service.LoginOtp("root", "root", "")
		assert.NoError(t, err)
		assert.NotNil(t, resp.AccessToken)
		assert.Equal(t, "access_token", resp.AccessToken)
	})
	t.Run("Should login with error in keycloak invalid otp", func(t *testing.T) {
		goCloakMock := &GoCloakMock{}
		goCloakMock.On("LoginOtp").Return(&gocloak.JWT{
			AccessToken:      "access_token",
			IDToken:          uuid.New().String(),
			ExpiresIn:        15,
			RefreshExpiresIn: 15,
			RefreshToken:     "refresh_token",
			TokenType:        "unique",
		}, nil)
		keycloakConfigMock := &Mock{}
		keycloakConfigMock.On("getClient").Return(goCloakMock)
		keycloakConfigMock.On("getClientID").Return("")
		keycloakConfigMock.On("getClientSecret").Return("")
		keycloakConfigMock.On("getRealm").Return("")
		keycloakConfigMock.On("getOtp").Return(true)
		service := &Service{
			ctx:          context.Background(),
			config:       keycloakConfigMock,
		}
		_, err := service.LoginOtp("root", "root", "")
		assert.Error(t, err)
	})
}

func Test_GetAccountIDByJWTToken(t *testing.T) {
	t.Run("Should GetAccountIDByJWTToken with success", func(t *testing.T) {
		email := "test@horusec.com"
		valid := true
		sub := uuid.New().String()

		goCloakMock := &GoCloakMock{}
		goCloakMock.On("RetrospectToken").Return(&gocloak.RetrospecTokenResult{Active: &valid}, nil)
		goCloakMock.On("IsActiveToken").Return(true, nil)
		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{
			Email: &email,
			Sub:   &sub,
		}, nil)

		keycloakConfigMock := &Mock{}
		keycloakConfigMock.On("getClient").Return(goCloakMock)
		keycloakConfigMock.On("getClientID").Return("")
		keycloakConfigMock.On("getClientSecret").Return("")
		keycloakConfigMock.On("getRealm").Return("")
		keycloakConfigMock.On("getOtp").Return(false)
		service := &Service{
			ctx:          context.Background(),
			config:       keycloakConfigMock,
		}

		userID, err := service.GetAccountIDByJWTToken("access_token")
		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, userID)
	})

	t.Run("Should GetAccountIDByJWTToken with error because user info return error", func(t *testing.T) {
		valid := true
		sub := uuid.New().String()

		goCloakMock := &GoCloakMock{}
		goCloakMock.On("RetrospectToken").Return(&gocloak.RetrospecTokenResult{Active: &valid}, nil)
		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{Sub: &sub}, errors.New("some error"))
		goCloakMock.On("IsActiveToken").Return(false, errors.New("error"))

		keycloakConfigMock := &Mock{}
		keycloakConfigMock.On("getClient").Return(goCloakMock)
		keycloakConfigMock.On("getClientID").Return("")
		keycloakConfigMock.On("getClientSecret").Return("")
		keycloakConfigMock.On("getRealm").Return("")
		keycloakConfigMock.On("getOtp").Return(false)
		service := &Service{
			ctx:          context.Background(),
			config:       keycloakConfigMock,
		}

		userID, err := service.GetAccountIDByJWTToken("access_token")
		assert.Error(t, err)
		assert.Equal(t, uuid.Nil, userID)
	})
}

func Test_IsActiveToken(t *testing.T) {
	t.Run("Should IsActiveToken with success and return active", func(t *testing.T) {
		goCloakMock := &GoCloakMock{}
		active := true
		goCloakMock.On("RetrospectToken").Return(&gocloak.RetrospecTokenResult{Active: &active}, nil)

		keycloakConfigMock := &Mock{}
		keycloakConfigMock.On("getClient").Return(goCloakMock)
		keycloakConfigMock.On("getClientID").Return("")
		keycloakConfigMock.On("getClientSecret").Return("")
		keycloakConfigMock.On("getRealm").Return("")
		keycloakConfigMock.On("getOtp").Return(false)
		service := &Service{
			ctx:          context.Background(),
			config:       keycloakConfigMock,
		}
		isActive, err := service.IsActiveToken("access_token")
		assert.NoError(t, err)
		assert.True(t, isActive)
	})
	t.Run("Should IsActiveToken with success and return inactive", func(t *testing.T) {
		goCloakMock := &GoCloakMock{}
		active := false
		goCloakMock.On("RetrospectToken").Return(&gocloak.RetrospecTokenResult{Active: &active}, nil)

		keycloakConfigMock := &Mock{}
		keycloakConfigMock.On("getClient").Return(goCloakMock)
		keycloakConfigMock.On("getClientID").Return("")
		keycloakConfigMock.On("getClientSecret").Return("")
		keycloakConfigMock.On("getRealm").Return("")
		keycloakConfigMock.On("getOtp").Return(false)
		service := &Service{
			ctx:          context.Background(),
			config:       keycloakConfigMock,
		}
		isActive, err := service.IsActiveToken("access_token")
		assert.NoError(t, err)
		assert.False(t, isActive)
	})
	t.Run("Should IsActiveToken with error", func(t *testing.T) {
		goCloakMock := &GoCloakMock{}
		goCloakMock.On("RetrospectToken").Return(&gocloak.RetrospecTokenResult{}, errors.New("error"))

		keycloakConfigMock := &Mock{}
		keycloakConfigMock.On("getClient").Return(goCloakMock)
		keycloakConfigMock.On("getClientID").Return("")
		keycloakConfigMock.On("getClientSecret").Return("")
		keycloakConfigMock.On("getRealm").Return("")
		keycloakConfigMock.On("getOtp").Return(false)
		service := &Service{
			ctx:          context.Background(),
			config:       keycloakConfigMock,
		}
		_, err := service.IsActiveToken("access_token")
		assert.Error(t, err)
	})
}

func TestService_GetUserInfo(t *testing.T) {
	t.Run("Should return UserInfo with success", func(t *testing.T) {
		goCloakMock := &GoCloakMock{}
		email := "test@horusec.com"
		valid := true

		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{Email: &email}, nil)
		goCloakMock.On("RetrospectToken").Return(&gocloak.RetrospecTokenResult{Active: &valid}, nil)
		goCloakMock.On("IsActiveToken").Return(true, nil)

		keycloakConfigMock := &Mock{}
		keycloakConfigMock.On("getClient").Return(goCloakMock)
		keycloakConfigMock.On("getClientID").Return("")
		keycloakConfigMock.On("getClientSecret").Return("")
		keycloakConfigMock.On("getRealm").Return("")
		keycloakConfigMock.On("getOtp").Return(false)
		service := &Service{
			ctx:          context.Background(),
			config:       keycloakConfigMock,
		}

		user, err := service.GetUserInfo("access_token")
		assert.NoError(t, err)
		assert.Equal(t, email, *user.Email)
	})

	t.Run("Should return UserInfo with error", func(t *testing.T) {
		goCloakMock := &GoCloakMock{}

		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{}, errors.New("error"))
		goCloakMock.On("RetrospectToken").Return(&gocloak.RetrospecTokenResult{}, errors.New("test"))

		keycloakConfigMock := &Mock{}
		keycloakConfigMock.On("getClient").Return(goCloakMock)
		keycloakConfigMock.On("getClientID").Return("")
		keycloakConfigMock.On("getClientSecret").Return("")
		keycloakConfigMock.On("getRealm").Return("")
		keycloakConfigMock.On("getOtp").Return(false)
		service := &Service{
			ctx:          context.Background(),
			config:       keycloakConfigMock,
		}

		_, err := service.GetUserInfo("access_token")
		assert.Error(t, err)
	})
}
