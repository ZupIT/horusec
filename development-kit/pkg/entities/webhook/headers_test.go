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

package webhook

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderType_Value(t *testing.T) {
	var h HeaderType
	h = []Headers{
		{
			Key:   "X-Horusec-Authorization",
			Value: "Bearer Token",
		},
	}
	response, err := h.Value()
	assert.NoError(t, err)
	assert.NotEmpty(t, response)
}

func TestHeaderType_Scan(t *testing.T) {
	t.Run("Should scan content to replace in gorm with error", func(t *testing.T) {
		var h HeaderType
		assert.Error(t, h.Scan("wrong type"))
	})
	t.Run("Should scan content to replace in gorm with success", func(t *testing.T) {
		var h HeaderType
		bytes, err := json.Marshal([]Headers{
			{
				Key:   "X-Horusec-Authorization",
				Value: "Bearer Token",
			},
		})
		assert.NoError(t, err)
		assert.NotEmpty(t, bytes)
		assert.NoError(t, h.Scan(bytes))
	})
}
