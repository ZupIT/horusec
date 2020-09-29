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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestIsMemberRepository(t *testing.T) {
	t.Run("should return 200 when everything its alright", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp.SetData(&roles.AccountRepository{}))

		middleware := NewRepositoryAuthzMiddleware(mockRead, mockWrite)
		handler := middleware.IsRepositoryMember(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)
		req = setRequestAuthorizationHeader(req)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("should return 403 when unable to find account", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))

		middleware := NewRepositoryAuthzMiddleware(mockRead, mockWrite)
		handler := middleware.IsRepositoryMember(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)
		req = setRequestAuthorizationHeader(req)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("should return 401 when invalid jwt token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		middleware := NewRepositoryAuthzMiddleware(mockRead, mockWrite)
		handler := middleware.IsRepositoryMember(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestIsAdminRepository(t *testing.T) {
	t.Run("should return 200 when everything its alright", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		accountCompany := &roles.AccountRepository{
			AccountID: uuid.New(),
			Role:      "admin",
		}

		resp := response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp.SetData(accountCompany))

		middleware := NewRepositoryAuthzMiddleware(mockRead, mockWrite)
		handler := middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)
		req = setRequestAuthorizationHeader(req)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("should return 403 when invalid role", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		accountCompany := &roles.AccountCompany{
			AccountID: uuid.New(),
			Role:      "member",
		}

		resp := response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp.SetData(accountCompany))

		middleware := NewRepositoryAuthzMiddleware(mockRead, mockWrite)
		handler := middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)
		req = setRequestAuthorizationHeader(req)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("should return 403 when find return error", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))

		middleware := NewRepositoryAuthzMiddleware(mockRead, mockWrite)
		handler := middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)
		req = setRequestAuthorizationHeader(req)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("should return 401 when invalid jwt token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		middleware := NewRepositoryAuthzMiddleware(mockRead, mockWrite)
		handler := middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}
