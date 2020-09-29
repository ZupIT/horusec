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

package horusapi

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	enumHorusec "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSendAnalysis(t *testing.T) {
	t.Run("should send analysis with no errors", func(t *testing.T) {
		analysis := &horusec.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    enumHorusec.Running,
		}

		httpMock := &client.Mock{}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{StatusCode: 201}), nil)

		service := Service{
			httpUtil: httpMock,
			config:   &cliConfig.Config{RepositoryAuthorization: "test"},
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(analysis)
		})
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		analysis := &horusec.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    enumHorusec.Running,
		}

		readCloser := ioutil.NopCloser(strings.NewReader("test"))

		response := &http.Response{
			StatusCode: 401,
			Body:       readCloser,
		}

		httpMock := &client.Mock{}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(response), nil)

		service := Service{
			httpUtil: httpMock,
			config:   &cliConfig.Config{RepositoryAuthorization: "test"},
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(analysis)
		})
	})

	t.Run("should return error when sending request", func(t *testing.T) {
		analysis := &horusec.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    enumHorusec.Running,
		}

		response := &http.Response{}
		httpMock := &client.Mock{}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(response), errors.New("test"))

		service := Service{
			httpUtil: httpMock,
			config:   &cliConfig.Config{RepositoryAuthorization: "test"},
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(analysis)
		})
	})

	t.Run("should return nil when no authorization token", func(t *testing.T) {
		analysis := &horusec.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    enumHorusec.Running,
		}

		service := Service{
			config: &cliConfig.Config{},
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(analysis)
		})
	})

	t.Run("should return a new service", func(t *testing.T) {
		assert.NotEmpty(t, NewHorusecAPIService(&cliConfig.Config{}))
	})
}
