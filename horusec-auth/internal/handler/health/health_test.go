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

package health

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/ldap"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	"github.com/stretchr/testify/assert"
)

func TestNewHandler(t *testing.T) {
	t.Run("should create a new handler", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		handler := NewHandler(mockRead, mockWrite, nil)
		assert.NotNil(t, handler)
	})
}

func TestOptions(t *testing.T) {
	t.Run("should return 204 when options", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		handler := NewHandler(mockRead, mockWrite, nil)
		r, _ := http.NewRequest(http.MethodOptions, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestGet(t *testing.T) {
	t.Run("should return 200 everything its ok", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockLdap := &ldap.Mock{}

		mockRead.On("IsAvailable").Return(true)
		mockWrite.On("IsAvailable").Return(true)
		mockLdap.On("IsAvailable").Return(true)

		handler := Handler{
			postgresRead:  mockRead,
			postgresWrite: mockWrite,
			ldap:          mockLdap,
			appConfig:     &app.Config{AuthType: authEnums.Ldap},
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when something is wrong with postgres", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		mockRead.On("IsAvailable").Return(false)
		mockWrite.On("IsAvailable").Return(true)

		handler := NewHandler(mockRead, mockWrite, &app.Config{AuthType: authEnums.Horusec})
		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	//t.Run("should return 500 when something is wrong with ldap", func(t *testing.T) {
	//	mockLdap := &ldap.Mock{}
	//
	//	mockLdap.On("IsAvailable").Return(false)
	//
	//	handler := Handler{
	//		ldap:      mockLdap,
	//		appConfig: &app.Config{AuthType: authEnums.Ldap},
	//	}
	//
	//	r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
	//	w := httptest.NewRecorder()
	//
	//	handler.Get(w, r)
	//
	//	assert.Equal(t, http.StatusInternalServerError, w.Code)
	//})
}
