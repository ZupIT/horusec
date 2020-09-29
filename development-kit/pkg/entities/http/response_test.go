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

package http

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestToBytes(t *testing.T) {
	t.Run("should success parse response struct to bytes", func(t *testing.T) {
		response := Response{}
		assert.NotNil(t, response.ToBytes())
	})
}

func TestToString(t *testing.T) {
	t.Run("should success parse response struct to string", func(t *testing.T) {
		response := Response{}
		assert.NotEmpty(t, response.ToString())
	})
}

func TestSetResponseData(t *testing.T) {
	t.Run("should success set response data", func(t *testing.T) {
		response := Response{}
		response.SetResponseData(http.StatusOK, http.StatusText(http.StatusOK), nil)

		assert.NotEmpty(t, response)
	})
}

func TestGetStatusCode(t *testing.T) {
	t.Run("should return status code 200", func(t *testing.T) {
		response := Response{}
		response.SetResponseData(http.StatusOK, http.StatusText(http.StatusOK), nil)

		assert.NotEmpty(t, response)
		assert.Equal(t, http.StatusOK, response.GetStatusCode())
	})
}
