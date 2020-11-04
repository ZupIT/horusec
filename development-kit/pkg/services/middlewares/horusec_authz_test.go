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
	"encoding/json"
	"errors"
	httpEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/http"
	httpClient "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewHorusAuthzMiddleware(t *testing.T) {
	t.Run("should create a new middleware service", func(t *testing.T) {
		middleware := NewHorusAuthzMiddleware(nil)
		assert.NotNil(t, middleware)
	})
}

func TestIsMember(t *testing.T) {
	t.Run("should return 200 when valid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: true})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		respBytes, _ = json.Marshal(httpEntities.Response{Content: uuid.New()})
		resp = &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsCompanyMember(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: false})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(resp), errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsCompanyMember(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestIsCompanyAdmin(t *testing.T) {
	t.Run("should return 200 when valid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: true})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		respBytes, _ = json.Marshal(httpEntities.Response{Content: uuid.New()})
		resp = &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsCompanyAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: false})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(resp), errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsCompanyAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestIsRepositoryMember(t *testing.T) {
	t.Run("should return 200 when valid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: true})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		respBytes, _ = json.Marshal(httpEntities.Response{Content: uuid.New()})
		resp = &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsRepositoryMember(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: false})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(resp), errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsRepositoryMember(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestIsRepositorySupervisor(t *testing.T) {
	t.Run("should return 200 when valid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: true})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		respBytes, _ = json.Marshal(httpEntities.Response{Content: uuid.New()})
		resp = &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsRepositorySupervisor(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: false})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(resp), errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsRepositorySupervisor(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("should return 401 when failed to unmarshall", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(""))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsRepositorySupervisor(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestIsRepositoryAdmin(t *testing.T) {
	t.Run("should return 200 when valid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: true})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		respBytes, _ = json.Marshal(httpEntities.Response{Content: uuid.New()})
		resp = &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Once().Return(httpResponse.NewHTTPResponse(resp), nil)

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: false})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(resp), errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestSetContextAccountID(t *testing.T) {
	t.Run("should return 200 when success set context", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: uuid.New()})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(resp), nil)

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.SetContextAccountID(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when failed to set context", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		respBytes, _ := json.Marshal(httpEntities.Response{Content: uuid.New()})
		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(string(respBytes)))}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(resp), errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.SetContextAccountID(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("should return 401 when failed to parse body", func(t *testing.T) {
		httpMock := &httpClient.Mock{}

		resp := &http.Response{Body: ioutil.NopCloser(strings.NewReader(""))}
		httpMock.On("DoRequest").Return(httpResponse.NewHTTPResponse(resp), nil)

		middleware := HorusAuthzMiddleware{
			httpUtil: httpMock,
		}

		handler := middleware.SetContextAccountID(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
