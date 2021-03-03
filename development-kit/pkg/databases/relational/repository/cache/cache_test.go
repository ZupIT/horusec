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

package cache

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	"os"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	expiredkeys "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache/expired_keys"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("tmp")
	_ = os.MkdirAll("tmp", 0750)
	m.Run()
	_ = os.RemoveAll("tmp")
}

func TestNewCacheRepository(t *testing.T) {
	t.Run("Should create new cache repository without errors", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		c := NewCacheRepository(mockRead, mockWrite)
		assert.IsType(t, &Cache{}, c)
	})
}

func TestIntegration(t *testing.T) {
	value := account.Company{
		CompanyID:   uuid.New(),
		Name:        uuid.New().String(),
		Description: uuid.New().String(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	cacheEntity := &cache.Cache{
		Key:   uuid.New().String(),
		Value: value.ToBytes(),
	}

	mockRead := adapter.NewRepositoryRead()
	_ = mockRead.GetConnection().Table(cacheEntity.GetTable()).AutoMigrate(cacheEntity)
	mockRead.SetLogMode(true)

	mockWrite := adapter.NewRepositoryWrite()
	_ = mockWrite.GetConnection().Table(cacheEntity.GetTable()).AutoMigrate(cacheEntity)
	mockWrite.SetLogMode(true)

	c := NewCacheRepository(mockRead, mockWrite)

	err := c.Set(cacheEntity, time.Duration(2)*time.Second)
	assert.NoError(t, err)
	exists := c.Exists(cacheEntity.Key)
	assert.True(t, exists)
	existing, err := c.Get(cacheEntity.Key)
	assert.NoError(t, err)
	assert.Equal(t, existing.Key, cacheEntity.Key)
	assert.Equal(t, existing.Value, cacheEntity.Value)
	time.Sleep(time.Duration(2) * time.Second)
	existing, err = c.Get(cacheEntity.Key)
	assert.NoError(t, err)
	assert.Nil(t, existing.Value)
	assert.Empty(t, existing.Key)
	err = c.Set(cacheEntity, time.Duration(2)*time.Second)
	assert.NoError(t, err)
	err = c.Del(cacheEntity.Key)
	assert.NoError(t, err)
	exists = c.Exists(cacheEntity.Key)
	assert.False(t, exists)
}

func TestCache_Set(t *testing.T) {
	t.Run("Should set new value and return error on set new value", func(t *testing.T) {
		value := account.Company{
			CompanyID:   uuid.New(),
			Name:        uuid.New().String(),
			Description: uuid.New().String(),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		cacheEntity := &cache.Cache{
			Key:   uuid.New().String(),
			Value: value.ToBytes(),
		}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("CreateOrUpdate").Return(response.NewResponse(0, errors.New("some an error"), nil))
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, nil, nil))
		mockExpiredKeys := &expiredkeys.Mock{}
		mockExpiredKeys.On("RemoveKeysExpiredFromDatabase").Return()

		c := &Cache{mockRead, mockWrite, mockExpiredKeys}
		err := c.Set(cacheEntity, time.Duration(2)*time.Second)
		assert.Error(t, err)
	})
}

func TestCache_Get(t *testing.T) {
	t.Run("Should return existing item in cache", func(t *testing.T) {
		value := account.Company{
			CompanyID:   uuid.New(),
			Name:        uuid.New().String(),
			Description: uuid.New().String(),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		cacheEntity := &cache.Cache{
			Key:   uuid.New().String(),
			Value: value.ToBytes(),
		}

		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, nil, cacheEntity))
		mockRead.On("SetFilter").Return(conn)
		mockExpiredKeys := &expiredkeys.Mock{}
		mockExpiredKeys.On("RemoveKeysExpiredFromDatabase").Return()

		c := &Cache{mockRead, mockWrite, mockExpiredKeys}
		result, err := c.Get(uuid.New().String())
		assert.NoError(t, err)
		assert.NotEmpty(t, result.Key)
		assert.NotNil(t, result.Value)
		assert.Equal(t, result.Value, cacheEntity.Value)
	})
	t.Run("Should return unexpected error when get cache", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, errors.New("some error"), nil))
		mockRead.On("SetFilter").Return(conn)
		mockExpiredKeys := &expiredkeys.Mock{}
		mockExpiredKeys.On("RemoveKeysExpiredFromDatabase").Return()

		c := &Cache{mockRead, mockWrite, mockExpiredKeys}
		_, err := c.Get(uuid.New().String())
		assert.Error(t, err)
		assert.NotEqual(t, err, errorsEnum.ErrNotFoundRecords)
	})
}

func TestCache_Exists(t *testing.T) {
	t.Run("Should return false when check if exists key in cache because return error on find", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, errors.New("some error"), nil))
		mockRead.On("SetFilter").Return(conn)
		mockExpiredKeys := &expiredkeys.Mock{}
		mockExpiredKeys.On("RemoveKeysExpiredFromDatabase").Return()

		c := &Cache{mockRead, mockWrite, mockExpiredKeys}
		existing := c.Exists(uuid.New().String())
		assert.False(t, existing)
	})
}

func TestCache_Del(t *testing.T) {
	t.Run("Should return false when check if exists key in cache because return error on find", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, errors.New("some error"), nil))
		mockRead.On("SetFilter").Return(conn)
		mockExpiredKeys := &expiredkeys.Mock{}
		mockExpiredKeys.On("RemoveKeysExpiredFromDatabase").Return()

		c := &Cache{mockRead, mockWrite, mockExpiredKeys}
		existing := c.Exists(uuid.New().String())
		assert.False(t, existing)
	})
}

func TestMock(t *testing.T) {
	t.Run("Should return get mock correctly", func(t *testing.T) {
		m := &Mock{}
		m.On("Get").Return(&cache.Cache{}, nil)
		existing, err := m.Get(uuid.New().String())
		assert.NoError(t, err)
		assert.NotNil(t, existing)
	})
	t.Run("Should return set mock correctly", func(t *testing.T) {
		m := &Mock{}
		m.On("Set").Return(nil)
		err := m.Set(&cache.Cache{}, time.Duration(5)*time.Second)
		assert.NoError(t, err)
	})
	t.Run("Should return del mock correctly", func(t *testing.T) {
		m := &Mock{}
		m.On("Del").Return(nil)
		err := m.Del(uuid.New().String())
		assert.NoError(t, err)
	})
	t.Run("Should return exists mock correctly", func(t *testing.T) {
		m := &Mock{}
		m.On("Exists").Return(true)
		exists := m.Exists(uuid.New().String())
		assert.True(t, exists)
	})
}
