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
	"github.com/ZupIT/horusec/development-kit/pkg/entities/admin"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestConfig_GetHorusecAPIURL(t *testing.T) {
	t.Run("should return default horusec api url", func(t *testing.T) {
		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
		appConfig := NewConfig(mockReadAdmin)
		assert.Equal(t, "http://localhost:8006", appConfig.GetHorusecAPIURL())
	})
	t.Run("should return horusec api url changed", func(t *testing.T) {
		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
		assert.NoError(t, os.Setenv(EnvHorusecAPIURL, "http://my-host.com.br/api"))
		appConfig := NewConfig(mockReadAdmin)
		assert.Equal(t, "http://my-host.com.br/api", appConfig.GetHorusecAPIURL())
	})
}
func TestConfig_GetEnableApplicationAdmin(t *testing.T) {
	t.Run("should return disable application admin", func(t *testing.T) {
		mockReadAdmin := env.GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{HorusecEnableApplicationAdmin: "false"})
		appConfig := NewConfig(mockReadAdmin)
		assert.False(t, appConfig.GetEnableApplicationAdmin())
	})
	t.Run("should return enable application admin", func(t *testing.T) {
		mockReadAdmin := env.GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{HorusecEnableApplicationAdmin: "true"})
		appConfig := NewConfig(mockReadAdmin)
		assert.True(t, appConfig.GetEnableApplicationAdmin())
	})
}
func TestConfig_GetDisabledBroker(t *testing.T) {
	t.Run("should return default disable broker", func(t *testing.T) {
		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
		appConfig := NewConfig(mockReadAdmin)
		assert.Equal(t, false, appConfig.GetDisabledBroker())
	})
	t.Run("should return disable broker changed", func(t *testing.T) {
		mockReadAdmin := env.GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{HorusecDisabledBroker: "true"})
		appConfig := NewConfig(mockReadAdmin)
		assert.Equal(t, true, appConfig.GetDisabledBroker())
	})
}
func TestConfig_GetApplicationAdminData(t *testing.T) {
	t.Run("should return default application admin data", func(t *testing.T) {
		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
		appConfig := NewConfig(mockReadAdmin)
		data, err := appConfig.GetApplicationAdminData()
		assert.NoError(t, err)
		expectedData := &dto.CreateAccount{
			Email:    "horusec-admin@example.com",
			Password: "Devpass0*",
			Username: "horusec-admin",
		}
		assert.Equal(t, expectedData.ToString(), data.ToString())
	})
	t.Run("should return application admin data changed", func(t *testing.T) {
		mockReadAdmin := env.GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{HorusecApplicationAdminData: `{"email": "user@email.com"}`})
		appConfig := NewConfig(mockReadAdmin)
		data, err := appConfig.GetApplicationAdminData()
		assert.NoError(t, err)
		expectedData := &dto.CreateAccount{Email: "user@email.com"}
		assert.Equal(t, expectedData.ToString(), data.ToString())
	})
	t.Run("should return error on read application admin data changed", func(t *testing.T) {
		mockReadAdmin := env.GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{HorusecApplicationAdminData: `wrong content to parse`})
		appConfig := NewConfig(mockReadAdmin)
		data, err := appConfig.GetApplicationAdminData()
		assert.Error(t, err)
		assert.Nil(t, data)
	})
}
func TestConfig_GetAuthType(t *testing.T) {
	t.Run("Should return auth type default", func(t *testing.T) {
		t.Run("should return default auth type", func(t *testing.T) {
			mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
			appConfig := NewConfig(mockReadAdmin)
			assert.Equal(t, authEnums.Horusec, appConfig.GetAuthType())
		})
		t.Run("should return auth type changed", func(t *testing.T) {
			mockReadAdmin := env.GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{HorusecAuthType: authEnums.AuthorizationType(authEnums.Ldap).ToString()})
			appConfig := NewConfig(mockReadAdmin)
			assert.Equal(t, authEnums.Ldap, appConfig.GetAuthType())
		})
		t.Run("should return unknown auth type when is wrong", func(t *testing.T) {
			mockReadAdmin := env.GlobalAdminReadMock(0, nil, &admin.HorusecAdminConfig{HorusecAuthType: "test"})
			appConfig := NewConfig(mockReadAdmin)
			assert.Equal(t, authEnums.Unknown, appConfig.GetAuthType())
		})
	})
}
