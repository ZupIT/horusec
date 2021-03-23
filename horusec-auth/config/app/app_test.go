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
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfig_GetEnableApplicationAdmin(t *testing.T) {
	t.Run("should return enable application admin", func(t *testing.T) {
		appConfig := Config{
			EnableApplicationAdmin: false,
		}
		assert.False(t, appConfig.GetEnableApplicationAdmin())
	})
	t.Run("should return enable application admin", func(t *testing.T) {
		appConfig := Config{
			EnableApplicationAdmin: true,
		}
		assert.True(t, appConfig.GetEnableApplicationAdmin())
	})
}

func TestConfig_GetApplicationAdminData(t *testing.T) {
	t.Run("Should return default application admin", func(t *testing.T) {
		appConfig := NewConfig()
		account, err := appConfig.GetApplicationAdminData()
		assert.NoError(t, err)
		assert.NotEmpty(t, account)
	})
}

func TestConfig_GetAuthType(t *testing.T) {
	t.Run("Should return auth type default", func(t *testing.T) {
		appConfig := NewConfig()
		assert.Equal(t, authEnums.Horusec, appConfig.GetAuthType())
	})
}

func TestConfig_GetHorusecAPIURL(t *testing.T) {
	t.Run("Should return horusec api default url", func(t *testing.T) {
		appConfig := NewConfig()
		assert.Equal(t, "http://localhost:8006", appConfig.GetHorusecAPIURL())
	})
}

func TestConfig_IsDisabledBroker(t *testing.T) {
	t.Run("Should return default is disabled broker", func(t *testing.T) {
		appConfig := NewConfig()
		assert.Equal(t, false, appConfig.IsDisabledBroker())
	})
}
