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

package account

import (
	"bytes"
	"errors"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"
	accountController "github.com/ZupIT/horusec/horusec-auth/internal/controller/account"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOptions(t *testing.T) {
	t.Run("should return status code 204 when options", func(t *testing.T) {
		handler := NewHandler(nil, nil)

		r, _ := http.NewRequest(http.MethodOptions, "api/account", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestHandler_CreateAccountFromKeycloak(t *testing.T) {
	t.Run("Should return 400 because body is empty", func(t *testing.T) {
		controllerMock := &accountController.Mock{}

		handler := &Handler{
			controller: controllerMock,
			useCases:   accountUseCases.NewAccountUseCases(),
		}

		r, _ := http.NewRequest(http.MethodPost, "test", nil)
		w := httptest.NewRecorder()

		handler.CreateAccountFromKeycloak(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Should return 400 because body is wrong", func(t *testing.T) {
		controllerMock := &accountController.Mock{}

		handler := &Handler{
			controller: controllerMock,
			useCases:   accountUseCases.NewAccountUseCases(),
		}

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader([]byte("invalid body")))
		w := httptest.NewRecorder()

		handler.CreateAccountFromKeycloak(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Should return 200 because user already registred", func(t *testing.T) {
		keycloak := &accountEntities.KeycloakToken{
			AccessToken: "Some token",
		}

		controllerMock := &accountController.Mock{}
		controllerMock.On("CreateAccountFromKeycloak").Return(errorsEnum.ErrorUsernameAlreadyInUse)

		handler := &Handler{
			controller: controllerMock,
			useCases:   accountUseCases.NewAccountUseCases(),
		}

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(keycloak.ToBytes()))
		w := httptest.NewRecorder()

		handler.CreateAccountFromKeycloak(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Should return 500 unexpected error", func(t *testing.T) {
		keycloak := &accountEntities.KeycloakToken{
			AccessToken: "Some token",
		}

		controllerMock := &accountController.Mock{}
		controllerMock.On("CreateAccountFromKeycloak").Return(errors.New("unexpected error"))

		handler := &Handler{
			controller: controllerMock,
			useCases:   accountUseCases.NewAccountUseCases(),
		}

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(keycloak.ToBytes()))
		w := httptest.NewRecorder()

		handler.CreateAccountFromKeycloak(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Should return 201 because new user login in system", func(t *testing.T) {
		keycloak := &accountEntities.KeycloakToken{
			AccessToken: "Some token",
		}

		controllerMock := &accountController.Mock{}
		controllerMock.On("CreateAccountFromKeycloak").Return(nil)

		handler := &Handler{
			controller: controllerMock,
			useCases:   accountUseCases.NewAccountUseCases(),
		}

		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(keycloak.ToBytes()))
		w := httptest.NewRecorder()

		handler.CreateAccountFromKeycloak(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

