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
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/admin"
	_ "github.com/jinzhu/gorm/dialects/sqlite" // Required in gorm usage
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnvOrDefault(t *testing.T) {
	_ = os.Setenv("TEST_ENV_VAR", "test-env-var")

	t.Run("should return the value of the env variable", func(t *testing.T) {
		r := GetEnvOrDefault("TEST_ENV_VAR", "test_default_value")
		assert.Equal(t, "test-env-var", r)
	})

	t.Run("should return default value", func(t *testing.T) {
		r := GetEnvOrDefault("TEST_DEFAULT_VALUE", "test_default_value")
		assert.Equal(t, "test_default_value", r)
	})
}

func TestGetEnvOrDefaultInt(t *testing.T) {
	_ = os.Setenv("TEST_ENV_VAR", "666")

	t.Run("should return the value of the env variable", func(t *testing.T) {
		r := GetEnvOrDefaultInt("TEST_ENV_VAR", 1010)
		assert.Equal(t, 666, r)
	})

	t.Run("should return default value", func(t *testing.T) {
		r := GetEnvOrDefaultInt("TEST_DEFAULT_VALUE", 1010)
		assert.Equal(t, 1010, r)
	})
}

func TestGetEnvOrDefaultInt64(t *testing.T) {
	_ = os.Setenv("TEST_ENV_VAR", "666")

	t.Run("should return the value of the env variable", func(t *testing.T) {
		r := GetEnvOrDefaultInt64("TEST_ENV_VAR", int64(1010))
		assert.Equal(t, int64(666), r)
	})

	t.Run("should return default value", func(t *testing.T) {
		r := GetEnvOrDefaultInt64("TEST_DEFAULT_VALUE", int64(1010))
		assert.Equal(t, int64(1010), r)
	})
}

func TestGetEnvOrDefaultAndParseToBool(t *testing.T) {
	t.Run("should return the value of the env variable with value true", func(t *testing.T) {
		_ = os.Setenv("TEST_ENV_VAR", "true")
		r := GetEnvOrDefaultBool("TEST_ENV_VAR", false)
		assert.Equal(t, true, r)
	})
	t.Run("should return the value of the env variable with value True", func(t *testing.T) {
		_ = os.Setenv("TEST_ENV_VAR", "True")
		r := GetEnvOrDefaultBool("TEST_ENV_VAR", false)
		assert.Equal(t, true, r)
	})
	t.Run("should return the value of the env variable with value 1", func(t *testing.T) {
		_ = os.Setenv("TEST_ENV_VAR", "1")
		r := GetEnvOrDefaultBool("TEST_ENV_VAR", false)
		assert.Equal(t, true, r)
	})
	t.Run("should return the value false if env not is true or 1", func(t *testing.T) {
		_ = os.Setenv("TEST_ENV_VAR", "generic")
		r := GetEnvOrDefaultBool("TEST_ENV_VAR", false)
		assert.Equal(t, false, r)
	})
	t.Run("should return default value", func(t *testing.T) {
		r := GetEnvOrDefaultBool("TEST_DEFAULT_VALUE", true)
		assert.Equal(t, true, r)
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

func TestGetEnvFromAdminDatabaseOrDefault(t *testing.T) {
	t.Run("should success get env from database of type boolean", func(t *testing.T) {
		mockRead := GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{HorusecEnableApplicationAdmin: "true"})
		r := GetEnvFromAdminOrDefault(mockRead, "HORUSEC_ENABLE_APPLICATION_ADMIN", "false").ToBool()
		assert.True(t, r)
	})
	t.Run("should success get env from database of type string", func(t *testing.T) {
		mockRead := GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{HorusecAuthType: "keycloak"})
		r := GetEnvFromAdminOrDefault(mockRead, "HORUSEC_AUTH_TYPE", "horusec").ToString()
		assert.Equal(t, r, "keycloak")
	})
	t.Run("should success get env from database of type int", func(t *testing.T) {
		mockRead := GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{HorusecLdapPort: "3000"})
		r := GetEnvFromAdminOrDefault(mockRead, "HORUSEC_LDAP_PORT", "5000").ToInt()
		assert.Equal(t, r, 3000)
	})
	t.Run("should success get env from database but if value is empty get value from environment", func(t *testing.T) {
		mockRead := GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{})
		r := GetEnvFromAdminOrDefault(mockRead, "HORUSEC_ENABLE_APPLICATION_ADMIN", "true").ToBool()
		assert.True(t, r)
	})
	t.Run("should return default content when database return nil value", func(t *testing.T) {
		mockRead := GlobalAdminReadMock(0, nil, nil)
		r := GetEnvFromAdminOrDefault(mockRead, "HORUSEC_ENABLE_APPLICATION_ADMIN", "false").ToBool()
		assert.False(t, r)
	})
	t.Run("should return env content when database return nil value", func(t *testing.T) {
		mockRead := GlobalAdminReadMock(0, nil, nil)
		assert.NoError(t, os.Setenv("HORUSEC_ENABLE_APPLICATION_ADMIN", "true"))
		r := GetEnvFromAdminOrDefault(mockRead, "HORUSEC_ENABLE_APPLICATION_ADMIN", "false").ToBool()
		assert.True(t, r)
	})
	t.Run("should error get env from database and return from env", func(t *testing.T) {
		mockRead := GlobalAdminReadMock(0, errors.New("test"), nil)
		r := GetEnvFromAdminOrDefault(mockRead, "HORUSEC_ENABLE_APPLICATION_ADMIN", "true").ToBool()
		assert.True(t, r)
	})
}
