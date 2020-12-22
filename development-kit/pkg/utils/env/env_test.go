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

package env

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnvOrDefault(t *testing.T) {
	_ = os.Setenv("TEST_ENV_VAR", "test-env-var")

	t.Run("should return the value of the env variable", func(t *testing.T) {
		response := GetEnvOrDefault("TEST_ENV_VAR", "test_default_value")
		assert.Equal(t, "test-env-var", response)
	})

	t.Run("should return default value", func(t *testing.T) {
		response := GetEnvOrDefault("TEST_DEFAULT_VALUE", "test_default_value")
		assert.Equal(t, "test_default_value", response)
	})
}

func TestGetEnvOrDefaultInt(t *testing.T) {
	_ = os.Setenv("TEST_ENV_VAR", "666")

	t.Run("should return the value of the env variable", func(t *testing.T) {
		response := GetEnvOrDefaultInt("TEST_ENV_VAR", 1010)
		assert.Equal(t, 666, response)
	})

	t.Run("should return default value", func(t *testing.T) {
		response := GetEnvOrDefaultInt("TEST_DEFAULT_VALUE", 1010)
		assert.Equal(t, 1010, response)
	})
}

func TestGetEnvOrDefaultInt64(t *testing.T) {
	_ = os.Setenv("TEST_ENV_VAR", "666")

	t.Run("should return the value of the env variable", func(t *testing.T) {
		response := GetEnvOrDefaultInt64("TEST_ENV_VAR", int64(1010))
		assert.Equal(t, int64(666), response)
	})

	t.Run("should return default value", func(t *testing.T) {
		response := GetEnvOrDefaultInt64("TEST_DEFAULT_VALUE", int64(1010))
		assert.Equal(t, int64(1010), response)
	})
}

func TestGetEnvOrDefaultAndParseToBool(t *testing.T) {
	t.Run("should return the value of the env variable with value true", func(t *testing.T) {
		_ = os.Setenv("TEST_ENV_VAR", "true")
		response := GetEnvOrDefaultBool("TEST_ENV_VAR", false)
		assert.Equal(t, true, response)
	})
	t.Run("should return the value of the env variable with value True", func(t *testing.T) {
		_ = os.Setenv("TEST_ENV_VAR", "True")
		response := GetEnvOrDefaultBool("TEST_ENV_VAR", false)
		assert.Equal(t, true, response)
	})
	t.Run("should return the value of the env variable with value 1", func(t *testing.T) {
		_ = os.Setenv("TEST_ENV_VAR", "1")
		response := GetEnvOrDefaultBool("TEST_ENV_VAR", false)
		assert.Equal(t, true, response)
	})
	t.Run("should return the value false if env not is true or 1", func(t *testing.T) {
		_ = os.Setenv("TEST_ENV_VAR", "generic")
		response := GetEnvOrDefaultBool("TEST_ENV_VAR", false)
		assert.Equal(t, false, response)
	})
	t.Run("should return default value", func(t *testing.T) {
		response := GetEnvOrDefaultBool("TEST_DEFAULT_VALUE", true)
		assert.Equal(t, true, response)
	})
}

func TestGetHorusecManagerURL(t *testing.T) {
	t.Run("should success get horusec manager URL default value", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_MANAGER_URL", "")
		assert.Equal(t, "http://localhost:8043", GetHorusecManagerURL())
	})

	t.Run("should success get horusec manager URL", func(t *testing.T) {
		_ = os.Setenv("HORUSEC_MANAGER_URL", "test-url.com")
		assert.Equal(t, "test-url.com", GetHorusecManagerURL())
	})
}

func TestGetEnvOrDefaultInterface(t *testing.T) {
	t.Run("should success get env as interface", func(t *testing.T) {
		_ = os.Setenv("TEST_ENV", "test")
		assert.Equal(t, "test", GetEnvOrDefaultInterface("TEST_ENV", "default"))
	})

	t.Run("should return default value", func(t *testing.T) {
		_ = os.Setenv("TEST_ENV", "")
		assert.Equal(t, "default", GetEnvOrDefaultInterface("TEST_ENV", "default"))
	})
}
