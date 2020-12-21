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
	"bytes"
	"errors"
	http2 "github.com/ZupIT/horusec/development-kit/pkg/entities/http"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
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
		config := &cliConfig.Config{}
		config.SetRepositoryAuthorization("test")
		config.SetHeaders(map[string]string{"some-header": "some-value"})

		service := Service{
			httpUtil: httpMock,
			config:   config,
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
		config := &cliConfig.Config{}
		config.SetRepositoryAuthorization("test")

		service := Service{
			httpUtil: httpMock,
			config:   config,
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
		config := &cliConfig.Config{}
		config.SetRepositoryAuthorization("test")

		service := Service{
			httpUtil: httpMock,
			config:   config,
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
	t.Run("should get analysis with error when set tls in request", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()

		httpMock := &client.Mock{}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{}), errors.New("test"))
		config := &cliConfig.Config{}
		config.SetRepositoryAuthorization("test")
		config.SetCertPath("./horus_api.go")
		config.SetCertInsecureSkipVerify(true)

		service := Service{
			httpUtil: httpMock,
			config:   config,
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(analysis)
		})
	})
	t.Run("should get analysis with error when set tls in request", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()

		httpMock := &client.Mock{}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{}), errors.New("test"))
		config := &cliConfig.Config{}
		config.SetRepositoryAuthorization("test")
		config.SetCertPath("./invalid_path")
		config.SetCertInsecureSkipVerify(true)

		service := Service{
			httpUtil: httpMock,
			config:   config,
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(analysis)
		})
	})
	t.Run("should return a new service", func(t *testing.T) {
		assert.NotEmpty(t, NewHorusecAPIService(&cliConfig.Config{}))
	})
}

func TestService_GetAnalysis(t *testing.T) {
	t.Run("should get analysis with no errors", func(t *testing.T) {
		analysisContent := test.CreateAnalysisMock()
		analysis := http2.Response{
			Code:    http.StatusOK,
			Status:  http.StatusText(http.StatusOK),
			Content: analysisContent,
		}
		body := ioutil.NopCloser(bytes.NewReader(analysis.ToBytes()))

		httpMock := &client.Mock{}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{StatusCode: 200, Body: body}), nil)
		config := &cliConfig.Config{}
		config.SetRepositoryAuthorization("test")

		service := Service{
			httpUtil: httpMock,
			config:   config,
		}

		analysisResponse := service.GetAnalysis(analysisContent.ID)
		assert.NotEmpty(t, analysisResponse)
		assert.NotEqual(t, uuid.Nil, analysisResponse.ID)
		assert.Len(t, analysisResponse.AnalysisVulnerabilities, 11)
	})
	t.Run("should get analysis with error because response is 400", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()
		body := ioutil.NopCloser(bytes.NewReader([]byte("uuid not valid in path")))

		httpMock := &client.Mock{}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{StatusCode: 400, Body: body}), nil)
		config := &cliConfig.Config{}
		config.SetRepositoryAuthorization("test")

		service := Service{
			httpUtil: httpMock,
			config:   config,
		}

		analysisResponse := service.GetAnalysis(analysis.ID)
		assert.Empty(t, analysisResponse)
	})
	t.Run("should get analysis with error when send request", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()

		httpMock := &client.Mock{}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{}), errors.New("some error"))
		config := &cliConfig.Config{}
		config.SetRepositoryAuthorization("test")

		service := Service{
			httpUtil: httpMock,
			config:   config,
		}

		analysisResponse := service.GetAnalysis(analysis.ID)
		assert.Empty(t, analysisResponse)
	})
	t.Run("should get analysis with error when set tls in request", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()

		httpMock := &client.Mock{}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{}), errors.New("some error"))
		config := &cliConfig.Config{}
		config.SetRepositoryAuthorization("test")
		config.SetCertPath("./invalid_path")
		config.SetCertInsecureSkipVerify(true)

		service := Service{
			httpUtil: httpMock,
			config:   config,
		}

		analysisResponse := service.GetAnalysis(analysis.ID)
		assert.Empty(t, analysisResponse)
	})

	t.Run("should return nil when no authorization token", func(t *testing.T) {
		service := Service{
			config: &cliConfig.Config{},
		}

		analysisResponse := service.GetAnalysis(uuid.Nil)
		assert.Empty(t, analysisResponse)
	})
}
