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
	"time"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	expiredkeys "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache/expired_keys"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

type Interface interface {
	Get(key string) (*cache.Cache, error)
	Exists(key string) bool
	Set(entity *cache.Cache, expiration time.Duration) error
	Del(key string) error
}

type Cache struct {
	databaseRead  SQL.InterfaceRead
	databaseWrite SQL.InterfaceWrite
	expiredKeys   expiredkeys.Interface
}

func NewCacheRepository(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) Interface {
	return &Cache{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
		expiredKeys:   expiredkeys.NewExpiredKeys(databaseRead, databaseWrite),
	}
}

func (c *Cache) Get(key string) (*cache.Cache, error) {
	c.expiredKeys.RemoveKeysExpiredFromDatabase()
	entity := &cache.Cache{}
	query := c.databaseRead.SetFilter(map[string]interface{}{"key": key})
	result := c.databaseRead.Find(entity, query, entity.GetTable())
	err := result.GetError()
	if err != nil {
		if result.GetData() == nil && err == errorsEnum.ErrNotFoundRecords {
			return &cache.Cache{Key: "", Value: nil}, nil
		}

		return &cache.Cache{Key: "", Value: nil}, err
	}
	return result.GetData().(*cache.Cache), nil
}

func (c *Cache) Exists(key string) bool {
	c.expiredKeys.RemoveKeysExpiredFromDatabase()
	entity := &cache.Cache{}
	query := c.databaseRead.SetFilter(map[string]interface{}{"key": key})
	result := c.databaseRead.Find(entity, query, entity.GetTable())
	if err := result.GetError(); err != nil && err != errorsEnum.ErrNotFoundRecords {
		logger.LogError("{HORUSEC_ACCOUNT} Error when check if key exists in cache table", err)
		return false
	}

	return result.GetData() != nil
}

func (c *Cache) Set(entity *cache.Cache, expiration time.Duration) error {
	c.expiredKeys.RemoveKeysExpiredFromDatabase()
	expiresAt := time.Now().Add(expiration)

	entity = entity.
		SetCreatedAt().
		SetExpiresAt(expiresAt)

	result := c.databaseWrite.CreateOrUpdate(entity, map[string]interface{}{"key": entity.Key}, entity.GetTable())

	return result.GetError()
}

func (c *Cache) Del(key string) error {
	c.expiredKeys.RemoveKeysExpiredFromDatabase()
	entity := &cache.Cache{}
	result := c.databaseWrite.Delete(map[string]interface{}{"key": key}, entity.GetTable())

	return result.GetError()
}
