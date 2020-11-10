package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	authController "github.com/ZupIT/horusec/horusec-auth/internal/controller/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthController(t *testing.T) {
	t.Run("should success create new controller", func(t *testing.T) {
		appConfig := &app.Config{}
		handler := NewAuthHandler(nil, nil, appConfig)
		assert.NotEmpty(t, handler)
	})
}

func TestOptions(t *testing.T) {
	t.Run("should return 204 when options", func(t *testing.T) {
		appConfig := &app.Config{}
		handler := NewAuthHandler(nil, nil, appConfig)
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
			appConfig:      &app.Config{},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(dto.Credentials{Username: "test", Password: "test"})

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
			appConfig:      &app.Config{},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(dto.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 400 when invalid credentials", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		handler := Handler{
			appConfig:      &app.Config{},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(dto.Credentials{})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_AuthTypes(t *testing.T) {
	t.Run("should return 200 when get auth types", func(t *testing.T) {
		handler := NewAuthHandler(nil, nil, &app.Config{
			AuthType: authEnums.Horusec,
		})

		r, _ := http.NewRequest(http.MethodGet, "test", nil)
		w := httptest.NewRecorder()

		handler.Config(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
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

	t.Run("should return 500 when something went wrong ldap", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errors.New("test"))

		handler := Handler{
			appConfig:      &app.Config{AuthType: authEnums.Ldap},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(dto.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 500 when something went wrong keycloak", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errors.New("test"))

		handler := Handler{
			appConfig:      &app.Config{AuthType: authEnums.Keycloak},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(dto.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 500 when something went wrong horusec", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errors.New("test"))

		handler := Handler{
			appConfig:      &app.Config{AuthType: authEnums.Horusec},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(dto.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 403 when email not confirmed", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errorsEnums.ErrorAccountEmailNotConfirmed)

		handler := Handler{
			appConfig:      &app.Config{AuthType: authEnums.Horusec},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(dto.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("should return 403 when wrong email or password", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errorsEnums.ErrorWrongEmailOrPassword)

		handler := Handler{
			appConfig:      &app.Config{AuthType: authEnums.Horusec},
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(dto.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horusec")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}
