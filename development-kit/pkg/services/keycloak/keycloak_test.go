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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Nerzal/gocloak/v7"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type HandlerMock struct {
	mock.Mock
}

func (f HandlerMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func TestNewKeycloakService(t *testing.T) {
	t.Run("Should return default type service keycloak", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		assert.IsType(t, NewKeycloakService(mockRead), &Service{})
	})
}

func TestService_LoginOtp(t *testing.T) {
	t.Run("Should login with success in keycloak", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		goCloakMock.On("LoginOtp").Return(&gocloak.JWT{
			AccessToken:      "access_token",
			IDToken:          uuid.New().String(),
			ExpiresIn:        15,
			RefreshExpiresIn: 15,
			RefreshToken:     "refresh_token",
			TokenType:        "unique",
		}, nil)
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}
		response, err := service.LoginOtp("root", "root", "")
		assert.NoError(t, err)
		assert.NotNil(t, response.AccessToken)
		assert.Equal(t, "access_token", response.AccessToken)
	})
	t.Run("Should login with error in keycloak invalid otp", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		goCloakMock.On("LoginOtp").Return(&gocloak.JWT{
			AccessToken:      "access_token",
			IDToken:          uuid.New().String(),
			ExpiresIn:        15,
			RefreshExpiresIn: 15,
			RefreshToken:     "refresh_token",
			TokenType:        "unique",
		}, nil)
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          true,
			databaseRead: mockRead,
		}
		_, err := service.LoginOtp("root", "root", "")
		assert.Error(t, err)
	})
}

func Test_GetAccountIDByJWTToken(t *testing.T) {
	t.Run("Should GetAccountIDByJWTToken with success", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		email := "test@horusec.com"
		entity := &account.Account{
			AccountID: uuid.New(),
			Email:     email,
		}
		mockRead.On("Find").Return(response.NewResponse(0, nil, entity))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		goCloakMock := &GoCloakMock{}
		goCloakMock.On("IsActiveToken").Return(true, nil)
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}
		userID, err := service.GetAccountIDByJWTToken("access_token")
		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, userID)
	})
	t.Run("Should GetAccountIDByJWTToken with error because user info return error", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		email := "test@horusec.com"
		entity := &account.Account{
			AccountID: uuid.New(),
			Email:     email,
		}
		mockRead.On("Find").Return(response.NewResponse(0, nil, entity))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		goCloakMock := &GoCloakMock{}
		goCloakMock.On("IsActiveToken").Return(false, errors.New("error"))
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}
		userID, err := service.GetAccountIDByJWTToken("access_token")
		assert.Error(t, err)
		assert.Equal(t, uuid.Nil, userID)
	})
	t.Run("Should GetAccountIDByJWTToken with error because find in repository return error", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		email := "test@horusec.com"
		entity := &account.Account{}
		mockRead.On("Find").Return(response.NewResponse(0, errors.New("error"), entity))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		goCloakMock := &GoCloakMock{}
		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{Email: &email}, nil)
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}
		userID, err := service.GetAccountIDByJWTToken("access_token")
		assert.Error(t, err)
		assert.Equal(t, uuid.Nil, userID)
	})
}

func Test_ValidateJWTToken(t *testing.T) {
	t.Run("Should ValidateJWTToken with success", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		email := "test@horusec.com"
		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{Email: &email}, nil)
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}

		w := httptest.NewRecorder()
		url := fmt.Sprintf("api/companies/%s/repositories/%s/tokens", uuid.New().String(), uuid.New().String())
		r, _ := http.NewRequest(http.MethodGet, url, nil)
		ctx := chi.NewRouteContext()
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		var handler HandlerMock
		newNext := service.ValidateJWTToken(handler)
		assert.NotEmpty(t, newNext)
		newNext.ServeHTTP(w, r)
		assert.Equal(t, http.StatusOK, w.Code)
	})
	t.Run("Should ValidateJWTToken with error 401 because token is not valid", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		email := "test@horusec.com"
		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{Email: &email}, errors.New("test"))
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}

		w := httptest.NewRecorder()
		url := fmt.Sprintf("api/companies/%s/repositories/%s/tokens", uuid.New().String(), uuid.New().String())
		r, _ := http.NewRequest(http.MethodGet, url, nil)
		ctx := chi.NewRouteContext()
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		var handler HandlerMock
		newNext := service.ValidateJWTToken(handler)
		assert.NotEmpty(t, newNext)
		newNext.ServeHTTP(w, r)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	t.Run("Should ValidateJWTToken with error 401 because token is not active", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		email := "test@horusec.com"
		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{Email: &email}, errors.New("test"))
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}

		w := httptest.NewRecorder()
		url := fmt.Sprintf("api/companies/%s/repositories/%s/tokens", uuid.New().String(), uuid.New().String())
		r, _ := http.NewRequest(http.MethodGet, url, nil)
		ctx := chi.NewRouteContext()
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		var handler HandlerMock
		newNext := service.ValidateJWTToken(handler)
		assert.NotEmpty(t, newNext)
		newNext.ServeHTTP(w, r)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	t.Run("Should ValidateJWTToken with error 401 because token is wrong in decode", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		email := "test@horusec.com"
		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{Email: &email}, errors.New("test"))
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}

		w := httptest.NewRecorder()
		url := fmt.Sprintf("api/companies/%s/repositories/%s/tokens", uuid.New().String(), uuid.New().String())
		r, _ := http.NewRequest(http.MethodGet, url, nil)
		ctx := chi.NewRouteContext()
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		var handler HandlerMock
		newNext := service.ValidateJWTToken(handler)
		assert.NotEmpty(t, newNext)
		newNext.ServeHTTP(w, r)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
func Test_IsActiveToken(t *testing.T) {
	t.Run("Should IsActiveToken with success and return active", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		active := true
		goCloakMock.On("RetrospectToken").Return(&gocloak.RetrospecTokenResult{Active: &active}, nil)
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}
		isActive, err := service.IsActiveToken("access_token")
		assert.NoError(t, err)
		assert.True(t, isActive)
	})
	t.Run("Should IsActiveToken with success and return inactive", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		active := false
		goCloakMock.On("RetrospectToken").Return(&gocloak.RetrospecTokenResult{Active: &active}, nil)
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}
		isActive, err := service.IsActiveToken("access_token")
		assert.NoError(t, err)
		assert.False(t, isActive)
	})
	t.Run("Should IsActiveToken with error", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		goCloakMock.On("RetrospectToken").Return(&gocloak.RetrospecTokenResult{}, errors.New("error"))
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}
		_, err := service.IsActiveToken("access_token")
		assert.Error(t, err)
	})
}

func TestService_GetUserInfo(t *testing.T) {
	t.Run("Should return UserInfo with success", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		email := "test@horusec.com"
		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{Email: &email}, nil)
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}
		user, err := service.GetUserInfo("access_token")
		assert.NoError(t, err)
		assert.Equal(t, email, *user.Email)
	})
	t.Run("Should return UserInfo with error", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		goCloakMock := &GoCloakMock{}
		goCloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{}, errors.New("error"))
		service := &Service{
			ctx:          context.Background(),
			client:       goCloakMock,
			clientID:     "",
			clientSecret: "",
			realm:        "",
			otp:          false,
			databaseRead: mockRead,
		}
		_, err := service.GetUserInfo("access_token")
		assert.Error(t, err)
	})
}
