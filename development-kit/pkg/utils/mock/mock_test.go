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

package mock

import (
	"testing"

	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/stretchr/testify/assert"
)

func TestReturnNilOrError(t *testing.T) {
	t.Run("should return nil when no args", func(t *testing.T) {
		err := ReturnNilOrError(nil, 2)
		assert.Nil(t, err)
	})

	t.Run("should return error when not nil", func(t *testing.T) {
		args := []interface{}{EnumErrors.ErrTest}
		err := ReturnNilOrError(args, 0)
		assert.Error(t, err)
	})
}

func TestReturnInt(t *testing.T) {
	t.Run("should return 1 when no args", func(t *testing.T) {
		result := ReturnInt(nil, 2)
		assert.Equal(t, 1, result)
	})

	t.Run("should return 9 when args", func(t *testing.T) {
		args := []interface{}{9}
		result := ReturnInt(args, 0)
		assert.Equal(t, 9, result)
	})
}

func TestReturnBool(t *testing.T) {
	t.Run("should return false when no args", func(t *testing.T) {
		result := ReturnBool(nil, 2)
		assert.False(t, result)
	})

	t.Run("should return true when set in args", func(t *testing.T) {
		args := []interface{}{true}
		result := ReturnBool(args, 0)
		assert.True(t, result)
	})
}
