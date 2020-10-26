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

package app

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetupApp(t *testing.T) {
	t.Run("should successfully create an application configuration struct", func(t *testing.T) {
		appConfig := SetupApp()
		assert.NotNil(t, appConfig)
	})
}

func TestIsEmailConfirmationRequired(t *testing.T) {
	t.Run("should return false as default value", func(t *testing.T) {
		appConfig := SetupApp()
		assert.False(t, appConfig.IsEmailServiceDisabled())
	})

	t.Run("should return false when env is setting it as false", func(t *testing.T) {
		_ = os.Setenv(DisableEmailServiceEnv, "true")
		appConfig := SetupApp()
		assert.True(t, appConfig.IsEmailServiceDisabled())
	})
}

func TestConfig_IsEnableApplicationAdmin(t *testing.T) {
	t.Run("should return enable application admin", func(t *testing.T) {
		appConfig := Config{
			EnableApplicationAdmin: false,
		}
		assert.False(t, appConfig.IsEnableApplicationAdmin())
	})
	t.Run("should return enable application admin", func(t *testing.T) {
		appConfig := Config{
			EnableApplicationAdmin: true,
		}
		assert.True(t, appConfig.IsEnableApplicationAdmin())
	})
}

func TestConfig_GetApplicationAdminData(t *testing.T) {
	t.Run("Should return default application admin", func(t *testing.T) {
		appConfig := SetupApp()
		account, err := appConfig.GetApplicationAdminData()
		assert.NoError(t, err)
		assert.NotEmpty(t, account)
	})
}
