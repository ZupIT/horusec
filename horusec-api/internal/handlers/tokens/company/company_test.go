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

package company

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	_ "gorm.io/driver/sqlite" // Required in gorm usage
)

func TestHandler_Post(t *testing.T) {
	t.Run("should return status 200 when successfully create a token", func(t *testing.T) {
		token := &api.Token{
			CompanyID:   uuid.New(),
			Description: "test",
		}

		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, nil, token))

		url := fmt.Sprintf("api/companies/%s/tokens", token.CompanyID.String())
		r, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(token.ToBytes()))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", token.CompanyID.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Post(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("should return status 422 when description is empty", func(t *testing.T) {
		token := &api.Token{
			CompanyID: uuid.New(),
		}

		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, nil, token))

		url := fmt.Sprintf("api/companies/%s/tokens", token.CompanyID.String())
		r, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(token.ToBytes()))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", token.CompanyID.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Post(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
	t.Run("should return status 422 when companyId is not valid", func(t *testing.T) {
		token := &api.Token{
			Description: "text",
		}

		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, nil, token))

		url := fmt.Sprintf("api/companies/some_text/tokens")
		r, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(token.ToBytes()))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", "some_text")

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Post(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
	t.Run("should return status 500 when repository return error on save token", func(t *testing.T) {
		token := &api.Token{
			CompanyID:   uuid.New(),
			Description: "text",
		}

		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, errors.New("error"), token))

		url := fmt.Sprintf("api/companies/%s/tokens", token.CompanyID.String())
		r, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(token.ToBytes()))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", token.CompanyID.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Post(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHandler_Delete(t *testing.T) {
	t.Run("should return status 204 when successfully delete a token", func(t *testing.T) {
		token := &api.Token{
			TokenID:     uuid.New(),
			CompanyID:   uuid.New(),
			Description: "test",
		}

		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Delete").Return(response.NewResponse(1, nil, nil))

		url := fmt.Sprintf("api/companies/%s/tokens/%s", token.CompanyID.String(), token.TokenID.String())
		r, _ := http.NewRequest(http.MethodDelete, url, nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", token.CompanyID.String())
		ctx.URLParams.Add("tokenID", token.TokenID.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Delete(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should return status 400 when parse tokenID fails", func(t *testing.T) {
		token := &api.Token{
			CompanyID:   uuid.New(),
			Description: "test",
		}

		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Delete").Return(response.NewResponse(0, nil, nil))

		url := fmt.Sprintf("api/companies/%s/tokens/invaliduuidstring", token.CompanyID.String())
		r, _ := http.NewRequest(http.MethodDelete, url, nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", token.CompanyID.String())
		ctx.URLParams.Add("tokenID", "invaliduuidstring")

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Delete(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status 400 when tokenID is nil", func(t *testing.T) {
		token := &api.Token{
			CompanyID:   uuid.New(),
			Description: "test",
		}

		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Delete").Return(response.NewResponse(0, nil, nil))

		url := fmt.Sprintf("api/companies/%s/tokens/%s", token.CompanyID.String(), uuid.Nil.String())
		r, _ := http.NewRequest(http.MethodDelete, url, nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", token.CompanyID.String())
		ctx.URLParams.Add("tokenID", uuid.Nil.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Delete(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status 404 when not exist token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Delete").Return(response.NewResponse(0, EnumErrors.ErrNotFoundRecords, nil))

		token := &api.Token{
			TokenID:     uuid.New(),
			CompanyID:   uuid.New(),
			Description: "test",
		}

		url := fmt.Sprintf("api/companies/%s/tokens/%s", token.CompanyID.String(), token.TokenID)
		r, _ := http.NewRequest(http.MethodDelete, url, nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", token.CompanyID.String())
		ctx.URLParams.Add("tokenID", token.TokenID.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Delete(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
	t.Run("should return status 500 when exist error on delete token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Delete").Return(response.NewResponse(0, errors.New("error"), nil))

		token := &api.Token{
			TokenID:     uuid.New(),
			CompanyID:   uuid.New(),
			Description: "test",
		}

		url := fmt.Sprintf("api/companies/%s/tokens/%s", token.CompanyID.String(), token.TokenID)
		r, _ := http.NewRequest(http.MethodDelete, url, nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", token.CompanyID.String())
		ctx.URLParams.Add("tokenID", token.TokenID.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Delete(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHandler_Get(t *testing.T) {
	t.Run("should return status 200 when successfully create a token", func(t *testing.T) {
		companyID := uuid.New()
		tokens := &[]api.Token{
			{
				TokenID:     uuid.New(),
				CompanyID:   companyID,
				Description: "test",
			},
			{
				TokenID:     uuid.New(),
				CompanyID:   companyID,
				Description: "test 2",
			},
		}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, nil, tokens))

		url := fmt.Sprintf("api/companies/%s/tokens", companyID.String())
		r, _ := http.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", companyID.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Get(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})
	t.Run("should return status 500 when return error on get content on database", func(t *testing.T) {
		companyID := uuid.New()
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, errors.New("error"), nil))

		url := fmt.Sprintf("api/companies/%s/tokens", companyID.String())
		r, _ := http.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", companyID.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("should return status 400 when companyID is invalid", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, errors.New("error"), nil))

		token := &api.Token{
			TokenID:     uuid.New(),
			CompanyID:   uuid.New(),
			Description: "test",
		}

		url := fmt.Sprintf("api/companies/%s/tokens/%s", uuid.Nil.String(), token.TokenID)
		r, _ := http.NewRequest(http.MethodDelete, url, nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("tokenID", token.TokenID.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Get(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_Options(t *testing.T) {
	t.Run("should return status 200 when successfully create a token", func(t *testing.T) {
		companyID := uuid.New()
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		url := fmt.Sprintf("api/companies/%s/tokens", companyID.String())
		r, _ := http.NewRequest(http.MethodOptions, url, nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", companyID.String())

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler := NewHandler(mockRead, mockWrite)
		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}
