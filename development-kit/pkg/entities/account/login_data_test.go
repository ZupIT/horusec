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
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/crypto"
	"github.com/stretchr/testify/assert"
)

func TestIsValid(t *testing.T) {
	t.Run("should return true for valid password with hash", func(t *testing.T) {
		loginData := LoginData{
			Password: "test",
			Email:    "test",
		}

		hash, err := crypto.HashPassword(loginData.Password)
		assert.NoError(t, err)
		assert.False(t, loginData.IsInvalid("test", hash))
	})

	t.Run("should return true for valid password with hash", func(t *testing.T) {
		loginData := LoginData{
			Password: "test",
			Email:    "test",
		}

		assert.True(t, loginData.IsInvalid("test", "test"))
	})
}

func TestValidateLoginData(t *testing.T) {
	t.Run("should return no errors for valid login data", func(t *testing.T) {
		loginData := LoginData{
			Password: "test",
			Email:    "test@test.com",
		}

		assert.NoError(t, loginData.Validate())
	})

	t.Run("should errors", func(t *testing.T) {
		loginData := LoginData{}
		assert.Error(t, loginData.Validate())
	})
}

func TestToBytesLoginData(t *testing.T) {
	t.Run("should success parse to bytes", func(t *testing.T) {
		loginData := LoginData{}
		assert.NotEmpty(t, loginData.ToBytes())
	})
}
