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

package account

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValues(t *testing.T) {
	t.Run("should return 2 roles values", func(t *testing.T) {
		assert.Len(t, Admin.Values(), 2)
	})
}

func TestIsValid(t *testing.T) {
	t.Run("should return true for valid value", func(t *testing.T) {
		assert.True(t, Admin.IsValid())
	})

	t.Run("should return false for valid value", func(t *testing.T) {
		assert.False(t, Unknown.IsValid())
	})
}
