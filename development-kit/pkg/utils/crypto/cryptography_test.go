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

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T) {
	t.Run("Should success return a hash of password with no errors", func(t *testing.T) {
		hash, err := HashPassword("test")
		assert.NoError(t, err)
		assert.NotEmpty(t, hash)
	})
}

func TestCheckPasswordHash(t *testing.T) {
	t.Run("Should return true for valid password", func(t *testing.T) {
		result := CheckPasswordHash("test", "$2a$10$CY6dyOjKD6rG.PxA6QlrLeUaHR.SD5VWLbkvc4YJM1ZT39geAIZQG")
		assert.True(t, result)
	})

	t.Run("Should return false for invalid password", func(t *testing.T) {
		result := CheckPasswordHash("invalid", "$2a$10$CY6dyOjKD6rG.PxA6QlrLeUaHR.SD5VWLbkvc4YJM1ZT39geAIZQG")
		assert.False(t, result)
	})
}

func TestHashToken(t *testing.T) {
	t.Run("Should success return a hash of token with no errors", func(t *testing.T) {
		hash := HashToken("test")
		assert.NotEmpty(t, hash)
	})
}
