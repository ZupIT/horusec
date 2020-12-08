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

	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	httpClient "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, nil)
		grpcMock.On("GetAccountID").Return(&authGrpc.GetAccountIDResponse{AccountID: uuid.New().String()}, nil)

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsCompanyMember(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsCompanyMember(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestIsCompanyAdmin(t *testing.T) {
	t.Run("should return 200 when valid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, nil)
		grpcMock.On("GetAccountID").Return(&authGrpc.GetAccountIDResponse{AccountID: uuid.New().String()}, nil)

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsCompanyAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsCompanyAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestIsRepositoryMember(t *testing.T) {
	t.Run("should return 200 when valid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, nil)
		grpcMock.On("GetAccountID").Return(&authGrpc.GetAccountIDResponse{AccountID: uuid.New().String()}, nil)

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsRepositoryMember(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsRepositoryMember(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestIsRepositorySupervisor(t *testing.T) {
	t.Run("should return 200 when valid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, nil)
		grpcMock.On("GetAccountID").Return(&authGrpc.GetAccountIDResponse{AccountID: uuid.New().String()}, nil)

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsRepositorySupervisor(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsRepositorySupervisor(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestIsRepositoryAdmin(t *testing.T) {
	t.Run("should return 200 when valid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, nil)
		grpcMock.On("GetAccountID").Return(&authGrpc.GetAccountIDResponse{AccountID: uuid.New().String()}, nil)

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}
		handler := middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsRepositoryAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestSetContextAccountID(t *testing.T) {
	t.Run("should return 200 when success set context", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("GetAccountID").Return(&authGrpc.GetAccountIDResponse{AccountID: uuid.New().String()}, nil)

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.SetContextAccountID(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when failed to set context", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("GetAccountID").Return(&authGrpc.GetAccountIDResponse{AccountID: uuid.New().String()}, errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.SetContextAccountID(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestIsApplicationAdmin(t *testing.T) {
	t.Run("should return 200 when valid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, nil)
		grpcMock.On("GetAccountID").Return(&authGrpc.GetAccountIDResponse{AccountID: uuid.New().String()}, nil)
		grpcMock.On("GetAuthConfig").Return(&authGrpc.GetAuthConfigResponse{AuthType: authEnums.Horusec.ToString(), ApplicationAdminEnable: true}, nil)

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsApplicationAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 401 when invalid request", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, errors.New("test"))
		grpcMock.On("GetAccountID").Return(&authGrpc.GetAccountIDResponse{AccountID: uuid.New().String()}, nil)
		grpcMock.On("GetAuthConfig").Return(&authGrpc.GetAuthConfigResponse{AuthType: authEnums.Horusec.ToString(), ApplicationAdminEnable: true}, nil)

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsApplicationAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("should return 401 when failed to get auth type", func(t *testing.T) {
		httpMock := &httpClient.Mock{}
		grpcMock := &authGrpc.Mock{}

		grpcMock.On("IsAuthorized").Return(&authGrpc.IsAuthorizedResponse{IsAuthorized: true}, errors.New("test"))
		grpcMock.On("GetAccountID").Return(&authGrpc.GetAccountIDResponse{AccountID: uuid.New().String()}, nil)
		grpcMock.On("GetAuthConfig").Return(&authGrpc.GetAuthConfigResponse{}, errors.New("test"))

		middleware := HorusAuthzMiddleware{
			httpUtil:   httpMock,
			grpcClient: grpcMock,
		}

		handler := middleware.IsApplicationAdmin(http.HandlerFunc(test.Handler))

		req, _ := http.NewRequest("GET", "http://test", nil)
		req.Header.Add("X-Horusec-Authorization", "123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
