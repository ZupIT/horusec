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

package client

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"

	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"github.com/stretchr/testify/assert"
)

func TestMock(t *testing.T) {
	t.Run("Should return mock correctly DoRequest", func(t *testing.T) {
		m := &Mock{}
		m.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{}), nil)
		res, err := m.DoRequest(&http.Request{}, &tls.Config{})
		assert.NotNil(t, res)
		assert.NoError(t, err)
	})
}

func TestNewHTTPClient(t *testing.T) {
	t.Run("Should not return empty", func(t *testing.T) {
		assert.NotEmpty(t, NewHTTPClient(10))
	})
}

func TestClient_DoRequest(t *testing.T) {
	t.Run("Should not return error when call request", func(t *testing.T) {
		urlToGet, err := url.Parse("https://zup.com.br")
		assert.NoError(t, err)
		req := &http.Request{
			Method: http.MethodGet,
			URL:    urlToGet,
		}
		response, err := NewHTTPClient(10).DoRequest(req, &tls.Config{})
		assert.NoError(t, err)
		assert.NotEmpty(t, response)
		defer func() {
			response.CloseBody()
		}()
	})
	t.Run("Should return error when request is wrong", func(t *testing.T) {
		req := &http.Request{}
		_, err := NewHTTPClient(10).DoRequest(req, &tls.Config{})
		assert.Error(t, err)
	})
}
