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
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestIsAuthorized(t *testing.T) {
	t.Run("should return 200 when token is authorized", func(t *testing.T) {
		mockRead := &relational.MockRead{}

		resp := response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		repositoryID := uuid.New()
		mockRead.On("Find").Return(resp.SetData(&api.Token{
			RepositoryID: &repositoryID,
			ExpiresAt:    time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day() + 1, time.Now().Hour(), time.Now().Minute(), time.Now().Second(), time.Now().Nanosecond(), time.Now().Location()),
		}))

		middleware := NewTokenAuthz(mockRead)
		handler := middleware.IsAuthorized(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when token is expired", func(t *testing.T) {
		mockRead := &relational.MockRead{}

		resp := response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		repositoryID := uuid.New()
		mockRead.On("Find").Return(resp.SetData(&api.Token{
			RepositoryID: &repositoryID,
			ExpiresAt:    time.Date(0, 0, 0, 0, 0, 0, 0, time.UTC),
			IsExpirable:  true,
		}))

		middleware := NewTokenAuthz(mockRead)
		handler := middleware.IsAuthorized(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("should return 401 when token is not present", func(t *testing.T) {
		mockRead := &relational.MockRead{}

		resp := response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		repositoryID := uuid.New()
		mockRead.On("Find").Return(resp.SetData(&api.Token{
			RepositoryID: &repositoryID,
			ExpiresAt:    time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day() + 1, time.Now().Hour(), time.Now().Minute(), time.Now().Second(), time.Now().Nanosecond(), time.Now().Location()),
		}))

		middleware := NewTokenAuthz(mockRead)
		handler := middleware.IsAuthorized(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("should return 401 when token does not exist", func(t *testing.T) {
		mockRead := &relational.MockRead{}

		resp := response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))

		middleware := NewTokenAuthz(mockRead)
		handler := middleware.IsAuthorized(http.HandlerFunc(test.Handler))
		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
