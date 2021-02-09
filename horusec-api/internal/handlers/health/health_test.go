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
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/grpc/health"
	"github.com/ZupIT/horusec/horusec-api/config/app"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/stretchr/testify/assert"
)

func TestNewHandler(t *testing.T) {
	t.Run("should create a new handler", func(t *testing.T) {
		postgresMockRead := &relational.MockRead{}
		postgresMockWrite := &relational.MockWrite{}

		handler := NewHandler(postgresMockRead, postgresMockWrite, nil, nil, nil)
		assert.NotNil(t, handler)
	})
}

func TestOptions(t *testing.T) {
	t.Run("should return 204 when options", func(t *testing.T) {
		postgresMockRead := &relational.MockRead{}
		postgresMockWrite := &relational.MockWrite{}

		handler := NewHandler(postgresMockRead, postgresMockWrite, nil, nil, nil)
		r, _ := http.NewRequest(http.MethodOptions, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestGet(t *testing.T) {
	t.Run("should return 200 everything its ok", func(t *testing.T) {
		postgresMockRead := &relational.MockRead{}
		postgresMockWrite := &relational.MockWrite{}
		mockGrpcService := &health.MockHealthCheckClient{}

		config := &app.Config{}
		config.SetDisabledBroker(false)

		brokerMock := &broker.Mock{}
		brokerMock.On("IsAvailable").Return(true)
		postgresMockRead.On("IsAvailable").Return(true)
		postgresMockWrite.On("IsAvailable").Return(true)
		mockGrpcService.On("IsAvailable").Return(true, "READY")

		handler := Handler{
			postgresRead:           postgresMockRead,
			postgresWrite:          postgresMockWrite,
			config:                 config,
			broker:                 brokerMock,
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})
	t.Run("should return 200 everything its ok and config disable", func(t *testing.T) {
		postgresMockRead := &relational.MockRead{}
		postgresMockWrite := &relational.MockWrite{}
		mockGrpcService := &health.MockHealthCheckClient{}
		config := &app.Config{}
		config.SetDisabledBroker(true)

		postgresMockRead.On("IsAvailable").Return(true)
		postgresMockWrite.On("IsAvailable").Return(true)
		mockGrpcService.On("IsAvailable").Return(true, "READY")

		handler := Handler{
			postgresRead:           postgresMockRead,
			postgresWrite:          postgresMockWrite,
			config:                 config,
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when broker is not healthy", func(t *testing.T) {
		postgresMockRead := &relational.MockRead{}
		postgresMockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}
		config := &app.Config{}
		config.SetDisabledBroker(false)

		brokerMock.On("IsAvailable").Return(false)
		postgresMockRead.On("IsAvailable").Return(true)
		postgresMockWrite.On("IsAvailable").Return(true)

		handler := Handler{
			postgresRead:  postgresMockRead,
			postgresWrite: postgresMockWrite,
			config:        config,
			broker:        brokerMock,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 500 when database write is not healthy", func(t *testing.T) {
		postgresMockRead := &relational.MockRead{}
		postgresMockWrite := &relational.MockWrite{}

		postgresMockWrite.On("IsAvailable").Return(true)
		postgresMockRead.On("IsAvailable").Return(false)

		config := &app.Config{}
		config.SetDisabledBroker(false)
		brokerMock := &broker.Mock{}
		brokerMock.On("IsAvailable").Return(true)

		handler := Handler{
			postgresRead:  postgresMockRead,
			postgresWrite: postgresMockWrite,
			config:        config,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 500 when database read is not healthy", func(t *testing.T) {
		postgresMockRead := &relational.MockRead{}
		postgresMockWrite := &relational.MockWrite{}

		postgresMockWrite.On("IsAvailable").Return(false)
		postgresMockRead.On("IsAvailable").Return(true)

		config := &app.Config{}
		config.SetDisabledBroker(false)
		brokerMock := &broker.Mock{}
		brokerMock.On("IsAvailable").Return(true)

		handler := Handler{
			postgresRead:  postgresMockRead,
			postgresWrite: postgresMockWrite,
			config:        config,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 500 when failed to connect to grpc", func(t *testing.T) {
		postgresMockRead := &relational.MockRead{}
		postgresMockWrite := &relational.MockWrite{}
		mockGrpcService := &health.MockHealthCheckClient{}

		config := &app.Config{}
		config.SetDisabledBroker(false)

		brokerMock := &broker.Mock{}
		brokerMock.On("IsAvailable").Return(true)
		postgresMockRead.On("IsAvailable").Return(true)
		postgresMockWrite.On("IsAvailable").Return(true)
		mockGrpcService.On("IsAvailable").Return(false, "TRANSIENT_FAILURE")

		handler := Handler{
			postgresRead:           postgresMockRead,
			postgresWrite:          postgresMockWrite,
			config:                 config,
			broker:                 brokerMock,
			grpcHealthCheckService: mockGrpcService,
		}

		r, _ := http.NewRequest(http.MethodGet, "api/health", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
