package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	authController "github.com/ZupIT/horusec/horusec-auth/internal/controller/auth"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAuthController(t *testing.T) {
	t.Run("should success create new controller", func(t *testing.T) {
		handler := NewAuthHandler(nil)
		assert.NotEmpty(t, handler)
	})
}

func TestOptions(t *testing.T) {
	t.Run("should return 204 when options", func(t *testing.T) {
		handler := NewAuthHandler(nil)
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
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horus")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthByType").Return(map[string]interface{}{"test": "test"}, errors.New("test"))

		handler := Handler{
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{Username: "test", Password: "test"})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horus")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 400 when invalid credentials", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		handler := Handler{
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		credentialsBytes, _ := json.Marshal(authEntities.Credentials{})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(credentialsBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horus")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 400 when invalid auth type", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		handler := Handler{
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		r, _ := http.NewRequest(http.MethodPost, "test", nil)
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "test")

		handler.AuthByType(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAuthorize(t *testing.T) {
	t.Run("should return 200 when successful authorize", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthorizeByType").Return(true, nil)

		handler := Handler{
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		dataBytes, _ := json.Marshal(authEntities.AuthorizationData{Token: "test", Groups: []string{"test"}})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horus")

		handler.Authorize(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		controllerMock.On("AuthorizeByType").Return(false, errors.New("test"))

		handler := Handler{
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		dataBytes, _ := json.Marshal(authEntities.AuthorizationData{Token: "test", Groups: []string{"test"}})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horus")

		handler.Authorize(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 400 when invalid authorization data", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		handler := Handler{
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		dataBytes, _ := json.Marshal(authEntities.AuthorizationData{})

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		r.Header.Add("X_AUTH_TYPE", "horus")

		handler.Authorize(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 400 when missing header", func(t *testing.T) {
		controllerMock := &authController.MockAuthController{}

		handler := Handler{
			authUseCases:   authUseCases.NewAuthUseCases(),
			authController: controllerMock,
		}

		r, _ := http.NewRequest(http.MethodPost, "test", nil)
		w := httptest.NewRecorder()

		handler.Authorize(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
