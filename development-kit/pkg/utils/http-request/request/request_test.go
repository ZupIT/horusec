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

package request

import (
	"io/ioutil"
	"math"
	"net/http"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/stretchr/testify/assert"
)

func TestMock(t *testing.T) {
	t.Run("Should return mock correctly Request", func(t *testing.T) {
		m := &Mock{}
		m.On("Request").Return(&http.Request{}, nil)
		res, err := m.Request("", "", nil, map[string]string{})
		assert.NotNil(t, res)
		assert.NoError(t, err)
	})
}

func TestNewHTTPRequest(t *testing.T) {
	t.Run("Should not return empty", func(t *testing.T) {
		assert.IsType(t, NewHTTPRequest(), &HTTPRequest{})
	})
}

func TestHTTPRequest_Request(t *testing.T) {
	t.Run("Should return error when body is invalid", func(t *testing.T) {
		_, err := NewHTTPRequest().Request("", "", math.NaN(), map[string]string{})
		assert.Error(t, err)
	})
	t.Run("Should return error method is wrong", func(t *testing.T) {
		_, err := NewHTTPRequest().Request("some method invalid", "", "", map[string]string{})
		assert.Error(t, err)
	})
	t.Run("Should return request without errors", func(t *testing.T) {
		req, err := NewHTTPRequest().Request(http.MethodGet, "https://zup.com.br", nil, map[string]string{})
		assert.NoError(t, err)
		assert.NotEmpty(t, req)
	})
	t.Run("Should return request without errors with body", func(t *testing.T) {
		req, err := NewHTTPRequest().Request(http.MethodGet, "https://zup.com.br", "some body", map[string]string{})
		assert.NoError(t, err)
		assert.NotEmpty(t, req)
		defer func() {
			logger.LogError("Error defer req.body close", req.Body.Close())
		}()
		bodyBytes, err := ioutil.ReadAll(req.Body)
		assert.NoError(t, err)
		assert.NotEmpty(t, string(bodyBytes))
	})
	t.Run("Should return request without errors with headers", func(t *testing.T) {
		req, err := NewHTTPRequest().Request(http.MethodGet, "https://zup.com.br", "some body", map[string]string{"Content-type": "application/json"})
		assert.NoError(t, err)
		assert.NotEmpty(t, req)
		assert.Equal(t, req.Header.Get("Content-type"), "application/json")
	})
}
