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
	"context"
	"encoding/json"
	"errors"
	entityCache "github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	t.Run("should return status code 204 when options", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodOptions, "api/account", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestCreateAccount(t *testing.T) {
	t.Run("should return status code 201 when created with success", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &accountEntities.Account{Email: "test@test.com", Username: "test", Password: "Test"}
		mockWrite.On("Create").Return(&response.Response{})
		brokerMock.On("Publish").Return(nil)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(account.ToBytes()))
		w := httptest.NewRecorder()

		handler.CreateAccount(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("should return status code 500 when some wrong happens", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &accountEntities.Account{Email: "test@test.com", Username: "test", Password: "Test"}
		mockWrite.On("Create").Return(&response.Response{})
		brokerMock.On("Publish").Return(errors.New("test"))

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(account.ToBytes()))
		w := httptest.NewRecorder()

		handler.CreateAccount(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 400 when email already in use", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &accountEntities.Account{Email: "test@test.com", Username: "test", Password: "Test"}
		mockWrite.On("Create").Return(&response.Response{})
		brokerMock.On("Publish").Return(errorsEnum.ErrorEmailAlreadyInUse)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(account.ToBytes()))
		w := httptest.NewRecorder()

		handler.CreateAccount(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status code 400 when invalid data", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{}

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(account.ToBytes()))
		w := httptest.NewRecorder()

		handler.CreateAccount(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestValidateEmail(t *testing.T) {
	t.Run("should return status ok 303 email is validated", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &accountEntities.Account{
			IsConfirmed: false,
		}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("accountID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.ValidateEmail(w, r)

		assert.Equal(t, 303, w.Code)
	})

	t.Run("should return status code 500 when something went wrong validating email", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("accountID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.ValidateEmail(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 400 when invalid request", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/test", nil)
		w := httptest.NewRecorder()

		handler.ValidateEmail(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestSendResetPasswordCode(t *testing.T) {
	t.Run("should return status code 204 when successful", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Set").Return(nil)
		brokerMock.On("Publish").Return(nil)

		data := &accountEntities.ResetCodeData{Email: "test@test.com", Code: "123456"}
		dataBytes, _ := json.Marshal(data)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		handler.SendResetPasswordCode(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Set").Return(nil)
		brokerMock.On("Publish").Return(errors.New("test"))

		data := &accountEntities.ResetCodeData{Email: "test@test.com", Code: "123456"}
		dataBytes, _ := json.Marshal(data)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		handler.SendResetPasswordCode(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 204 when email not found", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errorsEnum.ErrNotFoundRecords))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Set").Return(nil)

		data := &accountEntities.ResetCodeData{Email: "test@test.com", Code: "123456"}
		dataBytes, _ := json.Marshal(data)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		handler.SendResetPasswordCode(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should return 400 when invalid email", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		data := &accountEntities.EmailData{Email: "test"}
		dataBytes, _ := json.Marshal(data)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		handler.SendResetPasswordCode(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestValidateResetPasswordCode(t *testing.T) {
	t.Run("should return status code 200 when everything it is ok", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{}

		resp := &response.Response{}
		mockRead.On("Find").Once().Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("123456")}, nil)
		cacheRepositoryMock.On("Del").Return(nil)

		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))
		mockWrite.On("Update").Return(resp)

		data := &accountEntities.ResetCodeData{Email: "test@test.com", Code: "123456"}
		dataBytes, _ := json.Marshal(data)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		handler.ValidateResetPasswordCode(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when getting data in database", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("123456")}, nil)

		data := &accountEntities.ResetCodeData{Email: "test@test.com", Code: "123456"}
		dataBytes, _ := json.Marshal(data)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("email", "test@test.com")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.ValidateResetPasswordCode(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 401 when invalid code", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("2131231")}, nil)
		cacheRepositoryMock.On("Del").Return(nil)

		data := &accountEntities.ResetCodeData{Email: "test@test.com", Code: "123456"}
		dataBytes, _ := json.Marshal(data)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("email", "test@test.com")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.ValidateResetPasswordCode(w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("should return status code 400 when invalid email", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		data := &accountEntities.ResetCodeData{Email: "test", Code: "123456"}
		dataBytes, _ := json.Marshal(data)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		handler.ValidateResetPasswordCode(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestResetPassword(t *testing.T) {
	t.Run("should return status code 204 when password is changed", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		token, _, _ := jwt.CreateToken(account, nil)

		resp := &response.Response{}
		mockRead.On("Find").Once().Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)
		passwordBytes, _ := json.Marshal("123456")
		cacheRepositoryMock.On("Del").Return(nil)

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))
		mockWrite.On("Update").Return(resp)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(passwordBytes))
		w := httptest.NewRecorder()
		r.Header.Add("Authorization", token)

		handler.ChangePassword(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountID, uuid.New().String())))

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		token, _, _ := jwt.CreateToken(account, nil)

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp.SetError(errors.New("test")))
		passwordBytes, _ := json.Marshal("123456")

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(passwordBytes))
		w := httptest.NewRecorder()
		r.Header.Add("Authorization", token)

		handler.ChangePassword(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountID, uuid.New().String())))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 400 failed to parse password", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		token, _, _ := jwt.CreateToken(account, nil)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
		w := httptest.NewRecorder()
		r.Header.Add("Authorization", token)

		handler.ChangePassword(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountID, uuid.New().String())))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status code 401 when invalid token", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
		w := httptest.NewRecorder()

		handler.ChangePassword(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestRenewToken(t *testing.T) {
	t.Run("should return status 200 renewed token", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		token, _, _ := jwt.CreateToken(account, nil)

		resp := &response.Response{}
		mockRead.On("Find").Once().Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("test")}, nil)
		cacheRepositoryMock.On("Del").Return(nil)
		cacheRepositoryMock.On("Set").Return(nil)

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader([]byte("test")))
		w := httptest.NewRecorder()
		r.Header.Add("Authorization", token)

		handler.RenewToken(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status 401 when something went wrong", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		token, _, _ := jwt.CreateToken(account, nil)

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte(account.AccountID.String())}, errors.New("test"))
		cacheRepositoryMock.On("Del").Return(nil)
		cacheRepositoryMock.On("Set").Return(nil)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader([]byte("test")))
		w := httptest.NewRecorder()
		r.Header.Add("Authorization", token)

		handler.RenewToken(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("should return status 401 when missing authorization", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", nil)
		w := httptest.NewRecorder()

		handler.RenewToken(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status 401 when missing refresh token", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account", nil)
		w := httptest.NewRecorder()
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		token, _, _ := jwt.CreateToken(account, nil)
		r.Header.Add("Authorization", token)

		handler.RenewToken(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestLogout(t *testing.T) {
	account := &accountEntities.Account{
		IsConfirmed: false,
		AccountID:   uuid.New(),
		Email:       "test@test.com",
		Password:    "test",
		Username:    "test",
	}

	t.Run("should return status code 204 when successfully logout", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)
		cacheRepositoryMock.On("Del").Return(nil)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
		w := httptest.NewRecorder()

		token, _, _ := jwt.CreateToken(account, nil)
		r.Header.Add("Authorization", "Bearer "+token)

		handler.Logout(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountID, uuid.New().String())))

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should return status code 500 when something went wrong happened", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
		w := httptest.NewRecorder()

		token, _, _ := jwt.CreateToken(account, nil)
		r.Header.Add("Authorization", "Bearer "+token)

		handler.Logout(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountID, uuid.New().String())))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 401  when invalid  or missing token", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
		w := httptest.NewRecorder()

		handler.Logout(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestVerifyAlreadyInUse(t *testing.T) {
	t.Run("should return status code 200 when not in use", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &accountEntities.Account{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)

		validateUnique := &accountEntities.ValidateUnique{Email: "test@test.com", Username: "test"}
		validateUniqueBytes, _ := json.Marshal(validateUnique)

		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(validateUniqueBytes))
		w := httptest.NewRecorder()

		handler.VerifyAlreadyInUse(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 400 when username is already in use", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &accountEntities.Account{Username: "test"}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)

		validateUnique := &accountEntities.ValidateUnique{Email: "test@test.com", Username: "test"}
		validateUniqueBytes, _ := json.Marshal(validateUnique)

		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(validateUniqueBytes))
		w := httptest.NewRecorder()

		handler.VerifyAlreadyInUse(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status code 400 when email is already in use", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &accountEntities.Account{Email: "test@test.com"}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)

		validateUnique := &accountEntities.ValidateUnique{Email: "test@test.com", Username: "test"}
		validateUniqueBytes, _ := json.Marshal(validateUnique)

		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(validateUniqueBytes))
		w := httptest.NewRecorder()

		handler.VerifyAlreadyInUse(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status code 400 when invalid validate unique", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &accountEntities.Account{Email: "test@test.com"}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)

		validateUnique := &accountEntities.ValidateUnique{Email: "test", Username: "test"}
		validateUniqueBytes, _ := json.Marshal(validateUnique)

		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(validateUniqueBytes))
		w := httptest.NewRecorder()

		handler.VerifyAlreadyInUse(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestDeleteAccount(t *testing.T) {
	t.Run("should return 204 when success delete account", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		token, _, _ := jwt.CreateToken(account, nil)

		resp := &response.Response{}
		mockRead.On("Find").Once().Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Delete").Return(resp)

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
		w := httptest.NewRecorder()
		r.Header.Add("Authorization", token)

		handler.DeleteAccount(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountID, uuid.New().String())))

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		account := &accountEntities.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		token, _, _ := jwt.CreateToken(account, nil)

		resp := &response.Response{}
		mockRead.On("Find").Once().Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Delete").Return(resp.SetError(errors.New("test")))

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
		w := httptest.NewRecorder()
		r.Header.Add("Authorization", token)

		handler.DeleteAccount(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountID, uuid.New().String())))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 401 when invalid token", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		appConfig := app.SetupApp()
		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
		w := httptest.NewRecorder()
		r.Header.Add("Authorization", "invalid token")

		handler.DeleteAccount(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
