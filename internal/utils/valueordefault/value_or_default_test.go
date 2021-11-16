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

package valueordefault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetStringValueOrDefault(t *testing.T) {
	t.Run("should return string value", func(t *testing.T) {
		result := GetStringValueOrDefault("test", "default")
		assert.NotEmpty(t, result)
		assert.Equal(t, "test", result)
	})

	t.Run("should return default value", func(t *testing.T) {
		result := GetStringValueOrDefault("", "default")
		assert.NotEmpty(t, result)
		assert.Equal(t, "default", result)
	})
}

func TestGetInt64ValueOrDefault(t *testing.T) {
	t.Run("should return int value", func(t *testing.T) {
		result := GetInt64ValueOrDefault(int64(1), int64(2))
		assert.Equal(t, int64(1), result)
	})

	t.Run("should return default value", func(t *testing.T) {
		result := GetInt64ValueOrDefault(int64(0), int64(1))
		assert.Equal(t, int64(1), result)
	})
}

func TestGetSliceStringValueOrDefault(t *testing.T) {
	t.Run("should return slice string value", func(t *testing.T) {
		result := GetSliceStringValueOrDefault([]string{"./"}, []string{"123"})
		assert.NotEmpty(t, result)
		assert.Equal(t, []string{"./"}, result)
	})

	t.Run("should return slice default value", func(t *testing.T) {
		result := GetSliceStringValueOrDefault([]string{}, []string{"123"})
		assert.NotEmpty(t, result)
		assert.Equal(t, []string{"123"}, result)
	})
}
