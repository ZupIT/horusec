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

package middlewares

import (
	"context"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/jinzhu/gorm"
	"net/http"
	"net/http/httptest"
	"testing"

	entitiesAccount "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestIsRepositoryMember(t *testing.T) {
	t.Run("should return 200 when everything is ok", func(t *testing.T) {
		account := &entitiesAccount.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		permissions := map[string]string{"test": fmt.Sprint(accountEnums.Member)}
		token, _, _ := jwt.CreateToken(account, permissions)

		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "test")

		r := httptest.NewRequest(http.MethodPost, "/{repositoryID}", nil)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r.Header.Add("Authorization", "Bearer "+token)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		middleware := NewJWTAuthMiddleware(mockRead, mockWrite)

		middleware.IsRepositoryMember(http.HandlerFunc(test.Handler)).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when parse token fails", func(t *testing.T) {
		account := &entitiesAccount.Account{}
		permissions := map[string]string{"test": fmt.Sprint(accountEnums.Member)}
		token, _, _ := jwt.CreateToken(account, permissions)

		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "test")

		r := httptest.NewRequest(http.MethodPost, "/{repositoryID}", nil)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r.Header.Add("Authorization", "Bearer "+token)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		middleware := NewJWTAuthMiddleware(mockRead, mockWrite)

		middleware.IsRepositoryMember(http.HandlerFunc(test.Handler)).ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("should return 403 when entitiesAccount is not member", func(t *testing.T) {
		account := &entitiesAccount.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		token, _, _ := jwt.CreateToken(account, nil)

		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "test")

		r := httptest.NewRequest(http.MethodPost, "/{repositoryID}", nil)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r.Header.Add("Authorization", "Bearer "+token)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		mockRead.On("Find").Return(&response.Response{})
		mockRead.On("SetFilter").Return(&gorm.DB{})

		middleware := NewJWTAuthMiddleware(mockRead, mockWrite)

		middleware.IsRepositoryMember(http.HandlerFunc(test.Handler)).ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestIsRepositoryAdmin(t *testing.T) {
	t.Run("should return 200 when everything is ok", func(t *testing.T) {
		account := &entitiesAccount.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		permissions := map[string]string{"test": fmt.Sprint(accountEnums.Admin)}
		token, _, _ := jwt.CreateToken(account, permissions)

		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "test")

		r := httptest.NewRequest(http.MethodPost, "/{repositoryID}", nil)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r.Header.Add("Authorization", "Bearer "+token)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		mockRead.On("Find").Return(&response.Response{})
		mockRead.On("SetFilter").Return(&gorm.DB{})

		middleware := NewJWTAuthMiddleware(mockRead, mockWrite)

		middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler)).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when parse token fails", func(t *testing.T) {
		account := &entitiesAccount.Account{}
		permissions := map[string]string{"test": fmt.Sprint(accountEnums.Admin)}
		token, _, _ := jwt.CreateToken(account, permissions)

		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "test")

		r := httptest.NewRequest(http.MethodPost, "/{repositoryID}", nil)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r.Header.Add("Authorization", "Bearer "+token)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		mockRead.On("Find").Return(&response.Response{})
		mockRead.On("SetFilter").Return(&gorm.DB{})

		middleware := NewJWTAuthMiddleware(mockRead, mockWrite)

		middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler)).ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("should return 403 when entitiesAccount is not admin", func(t *testing.T) {
		account := &entitiesAccount.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		token, _, _ := jwt.CreateToken(account, nil)

		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "test")

		r := httptest.NewRequest(http.MethodPost, "/{repositoryID}", nil)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r.Header.Add("Authorization", "Bearer "+token)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		mockRead.On("Find").Return(&response.Response{})
		mockRead.On("SetFilter").Return(&gorm.DB{})

		middleware := NewJWTAuthMiddleware(mockRead, mockWrite)

		middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler)).ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("should return 403 when entitiesAccount is a membe", func(t *testing.T) {
		account := &entitiesAccount.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		permissions := map[string]string{"test": fmt.Sprint(accountEnums.Member)}
		token, _, _ := jwt.CreateToken(account, permissions)

		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "test")

		r := httptest.NewRequest(http.MethodPost, "/{repositoryID}", nil)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r.Header.Add("Authorization", "Bearer "+token)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		mockRead.On("Find").Return(&response.Response{})
		mockRead.On("SetFilter").Return(&gorm.DB{})

		middleware := NewJWTAuthMiddleware(mockRead, mockWrite)

		middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler)).ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestBindRepositoryPermissions(t *testing.T) {
	t.Run("should return 200 when everything is ok", func(t *testing.T) {
		account := &entitiesAccount.Account{
			AccountID: uuid.New(),
			Username:  "test",
			Email:     "test@test.com",
		}
		permissions := map[string]string{"test": fmt.Sprint(accountEnums.Admin)}
		token, _, _ := jwt.CreateToken(account, permissions)

		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "test")

		r := httptest.NewRequest(http.MethodPost, "/{repositoryID}", nil)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r.Header.Add("Authorization", "Bearer "+token)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		mockRead.On("Find").Return(&response.Response{})
		mockRead.On("SetFilter").Return(&gorm.DB{})

		middleware := NewJWTAuthMiddleware(mockRead, mockWrite)

		middleware.BindRepositoryPermissions(http.HandlerFunc(test.Handler)).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when parse token fails", func(t *testing.T) {
		account := &entitiesAccount.Account{}
		permissions := map[string]string{"test": fmt.Sprint(accountEnums.Admin)}
		token, _, _ := jwt.CreateToken(account, permissions)

		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "test")

		r := httptest.NewRequest(http.MethodPost, "/{repositoryID}", nil)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		r.Header.Add("Authorization", "Bearer "+token)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		mockRead.On("Find").Return(&response.Response{})
		mockRead.On("SetFilter").Return(&gorm.DB{})

		middleware := NewJWTAuthMiddleware(mockRead, mockWrite)

		middleware.BindRepositoryPermissions(http.HandlerFunc(test.Handler)).ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
