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
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	t.Run("should return status code 204 when options", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		handler := NewHandler(brokerMock, mockRead, mockWrite, &app.Config{}, &grpc.ClientConn{})

		r, _ := http.NewRequest(http.MethodOptions, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestGet(t *testing.T) {
	t.Run("should return status code 200 when everything its ok", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockGrpcService := &health.MockHealthCheckClient{}

		mockGrpcService.On("IsAvailable").Return(true, "READY")
		brokerMock.On("IsAvailable").Return(true)
		mockRead.On("IsAvailable").Return(true)
		mockWrite.On("IsAvailable").Return(true)

		handler := Handler{
			broker:                 brokerMock,
			databaseRead:           mockRead,
			databaseWrite:          mockWrite,
			appConfig:              &app.Config{},
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when database read is not ok", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockGrpcService := &health.MockHealthCheckClient{}

		mockGrpcService.On("IsAvailable").Return(false, "READY")
		brokerMock.On("IsAvailable").Return(true)
		mockRead.On("IsAvailable").Return(false)
		mockWrite.On("IsAvailable").Return(true)

		handler := Handler{
			broker:                 brokerMock,
			databaseRead:           mockRead,
			databaseWrite:          mockWrite,
			appConfig:              &app.Config{},
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 500 when database write is not ok", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockGrpcService := &health.MockHealthCheckClient{}

		mockGrpcService.On("IsAvailable").Return(false, "READY")
		brokerMock.On("IsAvailable").Return(true)
		mockRead.On("IsAvailable").Return(true)
		mockWrite.On("IsAvailable").Return(false)

		handler := Handler{
			broker:                 brokerMock,
			databaseRead:           mockRead,
			databaseWrite:          mockWrite,
			appConfig:              &app.Config{},
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 500 when broker it is not ok", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockGrpcService := &health.MockHealthCheckClient{}

		mockGrpcService.On("IsAvailable").Return(false, "READY")
		brokerMock.On("IsAvailable").Return(false)
		mockRead.On("IsAvailable").Return(true)
		mockWrite.On("IsAvailable").Return(true)

		handler := Handler{
			broker:                 brokerMock,
			databaseRead:           mockRead,
			databaseWrite:          mockWrite,
			appConfig:              &app.Config{},
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 500 when grpc failed to connect", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockGrpcService := &health.MockHealthCheckClient{}

		mockGrpcService.On("IsAvailable").Return(false, "TRANSIENT_FAILURE")
		brokerMock.On("IsAvailable").Return(true)
		mockRead.On("IsAvailable").Return(true)
		mockWrite.On("IsAvailable").Return(true)

		handler := Handler{
			broker:                 brokerMock,
			databaseRead:           mockRead,
			databaseWrite:          mockWrite,
			appConfig:              &app.Config{},
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
