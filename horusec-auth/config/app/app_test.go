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
