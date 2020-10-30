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
	"bytes"
	"encoding/json"
	"errors"
	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	authController "github.com/ZupIT/horusec/horusec-auth/internal/controller/auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthController(t *testing.T) {
	t.Run("should success create new controller", func(t *testing.T) {
		handler := NewAuthHandler(nil, nil, app.NewConfig())
		assert.NotEmpty(t, handler)
	})
}

func TestOptions(t *testing.T) {
	t.Run("should return 204 when options", func(t *testing.T) {
		handler := NewAuthHandler(nil, nil, app.NewConfig())
		r, _ := http.NewRequest(http.MethodOptions, "test", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestAuthByType(t *testing.T) {
	t.Run("should return 200 when successful login", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, nil)

		handler := Handler{
			appConfig: &app.Config{
				AuthType: authEnums.Horusec,
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errors.New("test"))

		handler := Handler{
			appConfig: &app.Config{
				AuthType: authEnums.Horusec,
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 400 when invalid credentials", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		handler := Handler{
			appConfig: &app.Config{
				AuthType: authEnums.Horusec,
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 403 when wrong password or username", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errorsEnums.ErrorWrongEmailOrPassword)

		handler := Handler{
			appConfig: &app.Config{
				AuthType: authEnums.Horusec,
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("should return 403 when email not confirmed", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errorsEnums.ErrorAccountEmailNotConfirmed)

		handler := Handler{
			appConfig: &app.Config{
				AuthType: authEnums.Horusec,
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("should return 500 when something went wrong in keycloak", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errorsEnums.ErrorAccountEmailNotConfirmed)

		handler := Handler{
			appConfig: &app.Config{
				AuthType: authEnums.Keycloak,
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 500 when something went wrong in keycloak", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errorsEnums.ErrorAccountEmailNotConfirmed)

		handler := Handler{
			appConfig: &app.Config{
				AuthType: authEnums.Ldap,
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errorsEnums.ErrorAccountEmailNotConfirmed)

		handler := Handler{
			appConfig: &app.Config{
				AuthType: "test",
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestAuthorize(t *testing.T) {
	t.Run("should return 200 when successful authorize", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthorizeByType").Return(true, nil)

		handler := Handler{
			appConfig:      &app.Config{},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		dataBytes, _ := json.Marshal(authEntities.AuthorizationData{Token: "test", Role: authEnums.RepositoryMember})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		handler.Authorize(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthorizeByType").Return(false, errors.New("test"))

		handler := Handler{
			appConfig:      &app.Config{},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		dataBytes, _ := json.Marshal(authEntities.AuthorizationData{Token: "test", Role: authEnums.RepositoryMember})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		handler.Authorize(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 400 when invalid data", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthorizeByType").Return(true, nil)

		handler := Handler{
			appConfig:      &app.Config{},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		dataBytes, _ := json.Marshal(authEntities.AuthorizationData{})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		handler.Authorize(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

}

func TestHandler_AuthTypes(t *testing.T) {
	t.Run("should return 200 when get auth types", func(t *testing.T) {
		handler := NewAuthHandler(nil, nil, app.NewConfig())

		r, _ := http.NewRequest(http.MethodGet, "test", nil)
		w := httptest.NewRecorder()

		handler.Config(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 400 when get auth types", func(t *testing.T) {
		handler := NewAuthHandler(nil, nil, &app.Config{AuthType: authEnums.Unknown})

		r, _ := http.NewRequest(http.MethodGet, "test", nil)
		w := httptest.NewRecorder()

		handler.Config(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 200 when get auth types mocked", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}
		controllerMock.On("GetAuthType").Return(authEnums.Horusec, nil)
		handler := Handler{
			appConfig: &app.Config{
				AuthType: "test",
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		r, _ := http.NewRequest(http.MethodGet, "test", nil)
		w := httptest.NewRecorder()

		handler.Config(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestGetAccountIDByAuthType(t *testing.T) {
	t.Run("should return 200 when get auth types", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}
		controllerMock.On("GetAccountIDByAuthType").Return(uuid.New(), nil)

		handler := Handler{
			appConfig: &app.Config{
				AuthType: authEnums.Horusec,
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		r, _ := http.NewRequest(http.MethodGet, "test", nil)
		w := httptest.NewRecorder()
		r.Header.Add("Authorization", "test")

		handler.GetAccountIDByAuthType(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when something went wrong getting id", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}
		controllerMock.On("GetAccountIDByAuthType").Return(uuid.Nil, errors.New("test"))

		handler := Handler{
			appConfig: &app.Config{
				AuthType: authEnums.Horusec,
			},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		r, _ := http.NewRequest(http.MethodGet, "test", nil)
		w := httptest.NewRecorder()
		r.Header.Add("Authorization", "test")

		handler.GetAccountIDByAuthType(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 500 when something went wrong getting id", func(t *testing.T) {
		handler := Handler{
			appConfig: &app.Config{
				AuthType: authEnums.Horusec,
			},
		}
		r, _ := http.NewRequest(http.MethodGet, "test", nil)
		w := httptest.NewRecorder()

		handler.GetAccountIDByAuthType(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
