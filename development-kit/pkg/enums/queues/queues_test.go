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

package queues

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValues(t *testing.T) {
	t.Run("should return all 5 queue values", func(t *testing.T) {
		assert.Len(t, Values(), 2)
	})
}

func TestIsInvalid(t *testing.T) {
	t.Run("should return false for valid queue value", func(t *testing.T) {
		assert.False(t, IsInvalid(HorusecEmail))
	})

	t.Run("should return true for invalid queue value", func(t *testing.T) {
		assert.True(t, IsInvalid("test"))
	})
}

func TestIsValid(t *testing.T) {
	t.Run("should return true for valid value", func(t *testing.T) {
		assert.True(t, IsValid(HorusecEmail))
	})

	t.Run("should return false for invalid value", func(t *testing.T) {
		assert.False(t, IsValid("test"))
	})
}

func TestValueOf(t *testing.T) {
	t.Run("should return value of horusec api queue", func(t *testing.T) {
		assert.Equal(t, HorusecEmail, ValueOf("horusec-email"))
	})

	t.Run("should return unknown for invalid value", func(t *testing.T) {
		assert.Equal(t, UNKNOWN, ValueOf("test"))
	})
}

func TestIsEqual(t *testing.T) {
	t.Run("should return true for equal value", func(t *testing.T) {
		assert.True(t, IsEqual("horusec-email", HorusecEmail))
	})

	t.Run("should return false for different value", func(t *testing.T) {
		assert.False(t, IsEqual("test", HorusecEmail))
	})
}

func TestToString(t *testing.T) {
	t.Run("should return parse queue to string", func(t *testing.T) {
		assert.NotEmpty(t, HorusecEmail.ToString())
	})
}
