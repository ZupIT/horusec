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
	"testing"

	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewResponse(t *testing.T) {
	t.Run("Should create new response and check if type is equal", func(t *testing.T) {
		assert.IsType(t, &Response{}, NewResponse(0, nil, nil))
	})
}

func TestResponse_Data(t *testing.T) {
	t.Run("Should create response with default data and set new data", func(t *testing.T) {
		valueToCompare := "generic_string_to_compare"
		res := NewResponse(0, nil, valueToCompare)

		assert.Equal(t, res.GetData(), valueToCompare)

		res.SetData("new_value")

		assert.NotEqual(t, res.GetData(), valueToCompare)
	})
}

func TestResponse_RowsAffected(t *testing.T) {
	t.Run("Should create response with default rowsAffected and set new rowsAffected", func(t *testing.T) {
		valueToCompare := 1
		res := NewResponse(valueToCompare, nil, "")

		assert.Equal(t, res.GetRowsAffected(), valueToCompare)

		res.SetRowsAffected(0)

		assert.NotEqual(t, res.GetRowsAffected(), valueToCompare)
	})
}

func TestResponse_Error(t *testing.T) {
	t.Run("Should create response with default error and set new error", func(t *testing.T) {
		res := NewResponse(0, nil, "")

		assert.Equal(t, res.GetError(), nil)

		res.SetError(EnumErrors.ErrTest)

		assert.NotEqual(t, res.GetError(), nil)
	})
}
