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

package repositories

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"

	"github.com/ZupIT/horusec/horusec-account/config/app"
	repositoriesController "github.com/ZupIT/horusec/horusec-account/internal/controller/repositories"
	repositoriesUseCases "github.com/ZupIT/horusec/horusec-account/internal/usecases/repositories"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func setAuthorizationHeader(r *http.Request) {
	account := &authEntities.Account{
		AccountID: uuid.New(),
		Email:     "test",
		Password:  "test",
		Username:  "test",
	}

	token, _, _ := jwt.CreateToken(account, nil)
	r.Header.Add("X-Horusec-Authorization", token)
}

func getRepositoryMock() *accountEntities.Repository {
	return &accountEntities.Repository{
		RepositoryID: uuid.New(),
		CompanyID:    uuid.New(),
		Name:         "test",
		Description:  "test",
	}
}

func TestCreate(t *testing.T) {
	t.Run("should return status created when everything it is ok", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp)
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(resp)

		respFind := &response.Response{}
		respFind.SetError(errorsEnum.ErrNotFoundRecords)
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repositoryBytes, _ := json.Marshal(getRepositoryMock())

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(repositoryBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, &authGrpc.GetAccountDataResponse{AccountID: uuid.New().String(), Permissions: []string{}}))

		handler.Create(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("should return internal server error when something went wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp.SetError(errors.New("test")))
		mockWrite.On("StartTransaction").Return(mockWrite)

		respFind := &response.Response{}
		respFind.SetError(errors.New("test"))
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repositoryBytes, _ := json.Marshal(getRepositoryMock())

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(repositoryBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, &authGrpc.GetAccountDataResponse{AccountID: uuid.New().String(), Permissions: []string{}}))

		handler.Create(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return internal server error when something went wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp.SetError(errors.New("test")))
		mockWrite.On("StartTransaction").Return(mockWrite)

		respFind := &response.Response{}
		respFind.SetError(errors.New("test"))
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repositoryBytes, _ := json.Marshal(getRepositoryMock())

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(repositoryBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, &authGrpc.GetAccountDataResponse{AccountID: uuid.New().String(), Permissions: []string{}}))

		handler.Create(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return bad request when invalid request body", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader([]byte("")))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Create(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return bad request when invalid company id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", nil)
		w := httptest.NewRecorder()

		handler.Create(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 400 when repository name already in use", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp.SetError(errorsEnum.ErrorRepositoryNameAlreadyInUse))
		mockWrite.On("StartTransaction").Return(mockWrite)

		respFind := &response.Response{}
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repositoryBytes, _ := json.Marshal(getRepositoryMock())

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(repositoryBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, &authGrpc.GetAccountDataResponse{AccountID: uuid.New().String(), Permissions: []string{}}))

		handler.Create(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestUpdate(t *testing.T) {
	t.Run("should return status no content when everything it is ok", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Return(resp.SetData(getRepositoryMock()))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repositoryBytes, _ := json.Marshal(getRepositoryMock())

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(repositoryBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return internal server error when something went wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repositoryBytes, _ := json.Marshal(getRepositoryMock())

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(repositoryBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return not found when not records found", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Return(resp.SetError(errorsEnum.ErrNotFoundRecords))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repositoryBytes, _ := json.Marshal(getRepositoryMock())

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(repositoryBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("should return bad request when invalid request body", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader([]byte("")))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return bad request when invalid repository id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", nil)
		w := httptest.NewRecorder()

		handler.Update(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestGet(t *testing.T) {
	t.Run("should return status ok when everything it is ok", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(getRepositoryMock()))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", nil)
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, &authGrpc.GetAccountDataResponse{AccountID: uuid.New().String(), Permissions: []string{}}))

		handler.Get(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return internal server error when something went wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", nil)
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, &authGrpc.GetAccountDataResponse{AccountID: uuid.New().String(), Permissions: []string{}}))

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return not found when no registry found", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errorsEnum.ErrNotFoundRecords))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", nil)
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, &authGrpc.GetAccountDataResponse{AccountID: uuid.New().String(), Permissions: []string{}}))

		handler.Get(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("should return bad request when invalid repository id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestUpdateAccountRepository(t *testing.T) {
	t.Run("should return status no content when everything its ok", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		acBytes, _ := json.Marshal(roles.AccountRepository{
			RepositoryID: uuid.New(),
			AccountID:    uuid.New(),
			Role:         accountEnums.Admin,
		})

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Return(resp.SetData(acBytes))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(acBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("accountID", uuid.New().String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		setAuthorizationHeader(r)

		handler.UpdateAccountRepository(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should return internal server error when something went wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		acBytes, _ := json.Marshal(roles.AccountRepository{
			RepositoryID: uuid.New(),
			AccountID:    uuid.New(),
			Role:         accountEnums.Admin,
		})

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(acBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("accountID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		setAuthorizationHeader(r)

		handler.UpdateAccountRepository(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return not found when no records were found", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		acBytes, _ := json.Marshal(roles.AccountRepository{
			RepositoryID: uuid.New(),
			AccountID:    uuid.New(),
			Role:         accountEnums.Admin,
		})

		resp := &response.Response{}
		respWithError := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Once().Return(resp.SetData(&authEntities.Account{}))
		mockRead.On("Find").Return(respWithError.SetError(errorsEnum.ErrNotFoundRecords))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(acBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("accountID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		setAuthorizationHeader(r)

		handler.UpdateAccountRepository(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("should return bad request when invalid request body", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader([]byte("")))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		setAuthorizationHeader(r)

		handler.UpdateAccountRepository(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return bad request when invalid repository id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader([]byte("")))
		w := httptest.NewRecorder()

		handler.UpdateAccountRepository(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 400 when invalid request body", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader([]byte("")))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		setAuthorizationHeader(r)

		handler.UpdateAccountRepository(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 400 when invalid or missing repository id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		acBytes, _ := json.Marshal(roles.AccountRepository{
			RepositoryID: uuid.New(),
			AccountID:    uuid.New(),
			Role:         accountEnums.Admin,
		})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(acBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		setAuthorizationHeader(r)

		handler.UpdateAccountRepository(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 400 when invalid or missing company id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		acBytes, _ := json.Marshal(roles.AccountRepository{
			RepositoryID: uuid.New(),
			AccountID:    uuid.New(),
			Role:         accountEnums.Admin,
		})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})
		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(acBytes))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		setAuthorizationHeader(r)

		handler.UpdateAccountRepository(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestInviteUser(t *testing.T) {
	inviteUser := &dto.InviteUser{
		Role:  "admin",
		Email: "test@test.com",
	}

	inviteUserBytes, _ := json.Marshal(inviteUser)

	repository := &accountEntities.Repository{
		CompanyID:    uuid.New(),
		RepositoryID: uuid.New(),
		Name:         "test",
	}

	account := &authEntities.Account{
		AccountID: uuid.New(),
		Email:     "test@test.com",
		Username:  "test",
	}

	t.Run("should return status 204 when everything it is ok", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		respRepository := &response.Response{}
		respAccount := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetData(account))
		mockRead.On("Find").Return(respRepository.SetData(repository))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Create").Return(respRepository)
		brokerMock.On("Publish").Return(nil)

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(inviteUserBytes))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.InviteUser(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should return status 409 when user already in repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		respRepository := &response.Response{}
		respAccount := &response.Response{}
		respWithError := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetData(account))
		mockRead.On("Find").Return(respRepository.SetData(repository))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Create").Return(
			respWithError.SetError(errors.New(errorsEnum.ErrorAlreadyExistingRepositoryID)))

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(inviteUserBytes))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.InviteUser(w, r)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("should return status 400 when invalid repository id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(inviteUserBytes))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.InviteUser(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status 400 when invalid company id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader(inviteUserBytes))
		w := httptest.NewRecorder()

		handler.InviteUser(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status 400 when invalid request body", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodPost, "api/repository", bytes.NewReader([]byte("")))
		w := httptest.NewRecorder()

		handler.InviteUser(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestList(t *testing.T) {
	account := &authEntities.Account{
		AccountID: uuid.New(),
		Email:     "test@test.com",
		Username:  "test",
	}

	t.Run("should return status 200 when everything it is ok", func(t *testing.T) {
		controllerMock := &repositoriesController.Mock{}
		controllerMock.On("List").Return(&[]accountEntities.RepositoryResponse{}, nil)

		handler := Handler{
			controller: controllerMock,
			useCases:   repositoriesUseCases.NewRepositoryUseCases(),
		}

		r, _ := http.NewRequest(http.MethodGet, "api/repository", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		token, _, _ := jwt.CreateToken(account, nil)
		r.Header.Add("X-Horusec-Authorization", token)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, &authGrpc.GetAccountDataResponse{AccountID: uuid.New().String(), Permissions: []string{}}))

		handler.List(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})
	t.Run("should return status 400 when companyID not exist in params", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		accountResp := &response.Response{}
		mockRead.On("First").Return(accountResp.SetData(account))

		repositories := &[]accountEntities.Repository{}
		repositoryResp := &response.Response{}
		mockRead.On("Related").Return(repositoryResp.SetData(repositories))

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodGet, "api/repository", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", "")
		token, _, _ := jwt.CreateToken(account, nil)
		r.Header.Add("X-Horusec-Authorization", token)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.List(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status 500 when something went wrong", func(t *testing.T) {
		controllerMock := &repositoriesController.Mock{}
		controllerMock.On("List").Return(&[]accountEntities.RepositoryResponse{}, errors.New("test"))

		handler := Handler{
			controller: controllerMock,
			useCases:   repositoriesUseCases.NewRepositoryUseCases(),
		}

		r, _ := http.NewRequest(http.MethodGet, "api/repository", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		token, _, _ := jwt.CreateToken(account, nil)
		r.Header.Add("X-Horusec-Authorization", token)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, &authGrpc.GetAccountDataResponse{AccountID: uuid.New().String(), Permissions: []string{}}))

		handler.List(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status 401 when invalid token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		accountResp := &response.Response{}
		mockRead.On("First").Return(accountResp.SetData(account))

		repositoryResp := &response.Response{}
		mockRead.On("Related").Return(repositoryResp.SetError(errors.New("test")))

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodGet, "api/repository", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r = r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, &authGrpc.GetAccountDataResponse{AccountID: "test", Permissions: []string{}}))

		handler.List(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestDeleteRepository(t *testing.T) {
	t.Run("should return 204 when success delete repository", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodDelete, "api/repositories/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Delete(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp.SetError(errors.New("test")))

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodDelete, "api/repositories/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Delete(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 400 when invalid request id", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodDelete, "api/repositories/", nil)
		w := httptest.NewRecorder()

		handler.Delete(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestGetAccountsFromRepository(t *testing.T) {
	t.Run("should return 200 when success get accounts", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		accounts := &[]roles.AccountRole{{Email: "test@test.com", Username: "test", Role: "member"}}

		accountsResp := &response.Response{}
		mockRead.On("RawSQL").Return(accountsResp.SetData(accounts))

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodGet, "api/companies/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetAccounts(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		accountsResp := &response.Response{}
		mockRead.On("RawSQL").Return(accountsResp.SetError(errors.New("test")))

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodGet, "api/companies/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetAccounts(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 400 when invalid company id", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodGet, "api/companies/", nil)
		w := httptest.NewRecorder()

		handler.GetAccounts(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestRemoveUser(t *testing.T) {
	account := authEntities.Account{}

	t.Run("should return 204 when successfully delete", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodDelete, "api/companies/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("accountID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.RemoveUser(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodDelete, "api/companies/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("accountID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.RemoveUser(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 404 when account was not found", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)
		mockRead.On("Find").Return(resp.SetError(errorsEnum.ErrNotFoundRecords))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodDelete, "api/companies/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("accountID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.RemoveUser(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("should return 400 when when missing or invalid account id", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodDelete, "api/companies/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.RemoveUser(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 400 when when missing or invalid repository id", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		handler := NewRepositoryHandler(mockWrite, mockRead, brokerMock, &app.Config{})

		r, _ := http.NewRequest(http.MethodDelete, "api/companies/", nil)
		w := httptest.NewRecorder()

		handler.RemoveUser(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
