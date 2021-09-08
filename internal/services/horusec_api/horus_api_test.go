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

package horusecapi

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ZupIT/horusec-devkit/pkg/services/http/request"

	entityHTTP "github.com/ZupIT/horusec-devkit/pkg/utils/http/entities"
	"github.com/ZupIT/horusec/internal/utils/mock"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	enumHorusec "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	httpResponse "github.com/ZupIT/horusec-devkit/pkg/services/http/request/entities"
	cliConfig "github.com/ZupIT/horusec/config"
)

func TestSendAnalysis(t *testing.T) {
	t.Run("should send analysis with no errors", func(t *testing.T) {
		entity := &analysis.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    enumHorusec.Running,
		}

		httpMock := &request.Mock{}
		httpMock.On("NewHTTPRequest").Return(&http.Request{}, nil)
		httpMock.On("DoRequest").Return(&httpResponse.HTTPResponse{Response: &http.Response{StatusCode: 201}}, nil)
		config := &cliConfig.Config{}
		config.RepositoryAuthorization = "test"
		config.Headers = map[string]string{"some-header": "some-value"}

		service := Service{
			http:   httpMock,
			config: config,
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(entity)
		})
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		entity := &analysis.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    enumHorusec.Running,
		}

		readCloser := ioutil.NopCloser(strings.NewReader("test"))

		response := &http.Response{
			StatusCode: 401,
			Body:       readCloser,
		}

		httpMock := &request.Mock{}
		httpMock.On("NewHTTPRequest").Return(&http.Request{}, nil)
		httpMock.On("DoRequest").Return(&httpResponse.HTTPResponse{Response: response}, nil)
		config := &cliConfig.Config{}
		config.RepositoryAuthorization = "test"

		service := Service{
			http:   httpMock,
			config: config,
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(entity)
		})
	})

	t.Run("should return error when sending request", func(t *testing.T) {
		entity := &analysis.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    enumHorusec.Running,
		}

		response := &http.Response{}
		httpMock := &request.Mock{}
		httpMock.On("NewHTTPRequest").Return(&http.Request{}, nil)
		httpMock.On("DoRequest").Return(&httpResponse.HTTPResponse{Response: response}, nil)
		config := &cliConfig.Config{}
		config.RepositoryAuthorization = "test"

		service := Service{
			http:   httpMock,
			config: config,
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(entity)
		})
	})

	t.Run("should return nil when no authorization token", func(t *testing.T) {
		entity := &analysis.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    enumHorusec.Running,
		}

		service := Service{
			config: &cliConfig.Config{},
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(entity)
		})
	})
	t.Run("should get analysis with error when set tls in request", func(t *testing.T) {
		entity := mock.CreateAnalysisMock()
		httpMock := &request.Mock{}
		httpMock.On("NewHTTPRequest").Return(&http.Request{}, nil)
		httpMock.On("DoRequest").Return(&httpResponse.HTTPResponse{Response: &http.Response{}}, nil)
		config := &cliConfig.Config{}
		config.RepositoryAuthorization = "test"
		config.CertPath = "./horus_api.go"
		config.CertInsecureSkipVerify = true

		service := Service{
			http:   httpMock,
			config: config,
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(entity)
		})
	})
	t.Run("should get analysis with error when set tls in request", func(t *testing.T) {
		entity := mock.CreateAnalysisMock()

		httpMock := &request.Mock{}
		httpMock.On("NewHTTPRequest").Return(&http.Request{}, nil)
		httpMock.On("DoRequest").Return(&httpResponse.HTTPResponse{Response: &http.Response{}}, nil)
		config := &cliConfig.Config{}
		config.RepositoryAuthorization = "test"
		config.CertPath = "./invalid_path"
		config.CertInsecureSkipVerify = true

		service := Service{
			http:   httpMock,
			config: config,
		}

		assert.NotPanics(t, func() {
			service.SendAnalysis(entity)
		})
	})
	t.Run("should return a new service", func(t *testing.T) {
		assert.NotEmpty(t, NewHorusecAPIService(&cliConfig.Config{}))
	})
}

func TestService_GetAnalysis(t *testing.T) {
	t.Run("should get analysis with no errors", func(t *testing.T) {
		analysisContent := mock.CreateAnalysisMock()
		entity := entityHTTP.Response{
			Code:    http.StatusOK,
			Status:  http.StatusText(http.StatusOK),
			Content: analysisContent,
		}
		body := ioutil.NopCloser(bytes.NewReader(entity.ToBytes()))

		httpMock := &request.Mock{}
		httpMock.On("NewHTTPRequest").Return(&http.Request{}, nil)
		httpMock.On("DoRequest").Return(&httpResponse.HTTPResponse{Response: &http.Response{StatusCode: 200, Body: body}}, nil)
		config := &cliConfig.Config{}
		config.RepositoryAuthorization = "test"

		service := Service{
			http:   httpMock,
			config: config,
		}

		analysisResponse := service.GetAnalysis(analysisContent.ID)
		assert.NotEmpty(t, analysisResponse)
		assert.NotEqual(t, uuid.Nil, analysisResponse.ID)
		assert.Len(t, analysisResponse.AnalysisVulnerabilities, 11)
	})
	t.Run("should get analysis with error because response is 400", func(t *testing.T) {
		entity := mock.CreateAnalysisMock()
		body := ioutil.NopCloser(bytes.NewReader([]byte("uuid not valid in path")))

		httpMock := &request.Mock{}
		httpMock.On("NewHTTPRequest").Return(&http.Request{}, nil)
		httpMock.On("DoRequest").Return(&httpResponse.HTTPResponse{Response: &http.Response{StatusCode: 400, Body: body}}, nil)
		config := &cliConfig.Config{}
		config.RepositoryAuthorization = "test"

		service := Service{
			http:   httpMock,
			config: config,
		}

		analysisResponse := service.GetAnalysis(entity.ID)
		assert.Empty(t, analysisResponse)
	})
	t.Run("should get analysis with error when send request", func(t *testing.T) {
		entity := mock.CreateAnalysisMock()

		httpMock := &request.Mock{}
		httpMock.On("NewHTTPRequest").Return(&http.Request{}, nil)
		httpMock.On("DoRequest").Return(&httpResponse.HTTPResponse{Response: &http.Response{}}, errors.New("some error"))
		config := &cliConfig.Config{}
		config.RepositoryAuthorization = "test"

		service := Service{
			http:   httpMock,
			config: config,
		}

		analysisResponse := service.GetAnalysis(entity.ID)
		assert.Empty(t, analysisResponse)
	})
	t.Run("should get analysis with error when set tls in request", func(t *testing.T) {
		entity := mock.CreateAnalysisMock()

		httpMock := &request.Mock{}
		httpMock.On("NewHTTPRequest").Return(&http.Request{}, errors.New("some error"))
		httpMock.On("DoRequest").Return(&httpResponse.HTTPResponse{Response: &http.Response{}}, nil)
		config := &cliConfig.Config{}
		config.RepositoryAuthorization = "test"
		config.CertPath = "./invalid_path"
		config.CertInsecureSkipVerify = true

		service := Service{
			http:   httpMock,
			config: config,
		}

		analysisResponse := service.GetAnalysis(entity.ID)
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
