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
	"github.com/ZupIT/horusec/development-kit/pkg/services/grpc/health"
	"google.golang.org/grpc"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/stretchr/testify/assert"
)

func TestNewHandler(t *testing.T) {
	t.Run("should success create a new handler", func(t *testing.T) {
		postgresMock := &relational.MockRead{}

		handler := NewHandler(postgresMock, &grpc.ClientConn{})
		assert.NotEmpty(t, handler)
	})
}

func TestHandler_Options(t *testing.T) {
	t.Run("should return 204 when call options", func(t *testing.T) {
		postgresMock := &relational.MockRead{}

		handler := NewHandler(postgresMock, &grpc.ClientConn{})

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestHandler_Get(t *testing.T) {
	t.Run("should return 200 when all dependence return success when call get", func(t *testing.T) {
		postgresMock := &relational.MockRead{}
		mockGrpcService := &health.MockHealthCheckClient{}

		postgresMock.On("IsAvailable").Return(true)
		mockGrpcService.On("IsAvailable").Return(true, "READY")

		handler := Handler{
			postgresRead:           postgresMock,
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when postgres database is not ok when call get", func(t *testing.T) {
		postgresMock := &relational.MockRead{}
		mockGrpcService := &health.MockHealthCheckClient{}

		postgresMock.On("IsAvailable").Return(false)
		mockGrpcService.On("IsAvailable").Return(true, "READY")

		handler := Handler{
			postgresRead:           postgresMock,
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 500 when failed to connect to grpc", func(t *testing.T) {
		postgresMock := &relational.MockRead{}
		mockGrpcService := &health.MockHealthCheckClient{}

		postgresMock.On("IsAvailable").Return(true)
		mockGrpcService.On("IsAvailable").Return(false, "TRANSIENT_FAILURE")

		handler := Handler{
			postgresRead:           postgresMock,
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
