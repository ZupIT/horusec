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

package response

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	enumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/stretchr/testify/assert"
)

func TestMock(t *testing.T) {
	t.Run("Should return mock correctly ErrorByStatusCode", func(t *testing.T) {
		m := &Mock{}
		m.On("ErrorByStatusCode").Return(nil)
		assert.NoError(t, m.ErrorByStatusCode())
	})
	t.Run("Should return mock correctly GetBody", func(t *testing.T) {
		m := &Mock{}
		m.On("GetBody").Return([]byte{}, nil)
		body, err := m.GetBody()
		assert.NoError(t, err)
		assert.NotNil(t, body)
	})
	t.Run("Should return mock correctly GetResponse", func(t *testing.T) {
		m := &Mock{}
		m.On("GetResponse").Return(&http.Response{})
		assert.NotNil(t, m.GetResponse())
	})
	t.Run("Should return mock correctly GetStatusCode", func(t *testing.T) {
		m := &Mock{}
		m.On("GetStatusCode").Return(200)
		assert.Equal(t, m.GetStatusCode(), 200)
	})
	t.Run("Should return mock correctly GetStatusCodeString", func(t *testing.T) {
		m := &Mock{}
		m.On("GetStatusCodeString").Return("OK")
		assert.NotEmpty(t, m.GetStatusCodeString())
	})
	t.Run("Should return mock correctly GetContentType", func(t *testing.T) {
		m := &Mock{}
		m.On("GetContentType").Return("application/json")
		assert.NotEmpty(t, m.GetContentType())
	})
}

func TestNewHTTPResponse(t *testing.T) {
	t.Run("Should not return empty", func(t *testing.T) {
		assert.NotEmpty(t, NewHTTPResponse(&http.Response{}))
	})
}

func TestHTTPResponse_GetStatusCode(t *testing.T) {
	t.Run("Should return status code 200 by response", func(t *testing.T) {
		res := &http.Response{
			StatusCode: 200,
		}
		assert.Equal(t, 200, NewHTTPResponse(res).GetStatusCode())
	})
}

func TestHTTPResponse_GetStatusCodeString(t *testing.T) {
	t.Run("Should return status code string `OK` by response", func(t *testing.T) {
		res := &http.Response{
			StatusCode: 200,
		}
		assert.Equal(t, "OK", NewHTTPResponse(res).GetStatusCodeString())
	})
}

func TestHTTPResponse_GetResponse(t *testing.T) {
	t.Run("Should return response equals passed", func(t *testing.T) {
		res := &http.Response{}
		assert.Equal(t, res, NewHTTPResponse(res).GetResponse())
	})
}

func TestHTTPResponse_GetContentType(t *testing.T) {
	t.Run("Should return content-type `application/json`", func(t *testing.T) {
		res := &http.Response{
			Header: map[string][]string{},
		}
		res.Header.Set("Content-type", "application/json")
		assert.Equal(t, "application/json", NewHTTPResponse(res).GetContentType())
	})
}

func TestHTTPResponse_ErrorByStatusCode(t *testing.T) {
	t.Run("Should return error server side", func(t *testing.T) {
		res := &http.Response{
			StatusCode: 500,
		}
		assert.Equal(t, enumErrors.ErrDoHTTPServiceSide, NewHTTPResponse(res).ErrorByStatusCode())
	})
	t.Run("Should return error client side", func(t *testing.T) {
		res := &http.Response{
			StatusCode: 400,
		}
		assert.Equal(t, enumErrors.ErrDoHTTPClientSide, NewHTTPResponse(res).ErrorByStatusCode())
	})
	t.Run("Should not return error", func(t *testing.T) {
		res := &http.Response{
			StatusCode: 200,
		}
		assert.Equal(t, nil, NewHTTPResponse(res).ErrorByStatusCode())
	})
}

func TestHTTPResponse_GetBody(t *testing.T) {
	t.Run("Should return body expected", func(t *testing.T) {
		bodyResponse := "hello world"
		res := &http.Response{
			Body: ioutil.NopCloser(strings.NewReader(bodyResponse)),
		}
		body, err := NewHTTPResponse(res).GetBody()
		assert.NoError(t, err)
		assert.Equal(t, bodyResponse, string(body))
	})
	t.Run("Should return body nil", func(t *testing.T) {
		res := &http.Response{}
		body, err := NewHTTPResponse(res).GetBody()
		assert.NoError(t, err)
		assert.Empty(t, body)
	})
}
