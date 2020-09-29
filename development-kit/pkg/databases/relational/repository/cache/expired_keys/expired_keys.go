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

package expiredkeys

import (
	"time"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

type Interface interface {
	RemoveKeysExpiredFromDatabase()
}

type ExpiredKeys struct {
	databaseRead  SQL.InterfaceRead
	databaseWrite SQL.InterfaceWrite
}

func NewExpiredKeys(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) Interface {
	return &ExpiredKeys{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
	}
}

func (e *ExpiredKeys) RemoveKeysExpiredFromDatabase() {
	keysExpired := e.getAllKeysExpired()
	if len(keysExpired) > 0 {
		e.deleteKeysExpired(keysExpired)
	}
}

func (e *ExpiredKeys) getAllKeysExpired() (keys []string) {
	entity := &cache.Cache{}
	listEntity := []cache.Cache{}
	query := e.databaseRead.GetConnection().Where("expires_at <= ?", time.Now())
	result := e.databaseRead.Find(&listEntity, query, entity.GetTable())
	if err := result.GetError(); err != nil && err != errorsEnum.ErrNotFoundRecords {
		logger.LogError("{CACHE_REPOSITORY} Error when find all keys expired", err)
		return keys
	}
	for _, item := range listEntity {
		keys = append(keys, item.Key)
	}
	return keys
}

func (e *ExpiredKeys) deleteKeysExpired(keysExpired []string) {
	entity := &cache.Cache{}
	query := e.databaseWrite.GetConnection().Where("key IN (?)", keysExpired)
	result := e.databaseWrite.DeleteByQuery(query, entity.GetTable())
	if err := result.GetError(); err != nil {
		logger.LogError("{CACHE_REPOSITORY} Error when delete keys expired in cache", err)
	}
	if result.GetRowsAffected() != len(keysExpired) {
		content := map[string]interface{}{
			"RowsAffected": result.GetRowsAffected(), "LengthKeysExpired": len(keysExpired), "KeysExpired": keysExpired}
		logger.LogInfo("{CACHE_REPOSITORY} Divergent content when remove keys expired in cache: ", content)
	}
}
