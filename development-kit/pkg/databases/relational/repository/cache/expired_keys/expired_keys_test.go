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
	"errors"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite" // Required in gorm usage
	"github.com/stretchr/testify/assert"
)

func TestExpiredKeys_RemoveKeysExpiredFromDatabase(t *testing.T) {
	t.Run("Should return empty key because return unexpected error on find keys", func(t *testing.T) {
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, errors.New("some error"), nil))
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("GetConnection").Return(conn)

		c := NewExpiredKeys(mockRead, mockWrite)
		c.RemoveKeysExpiredFromDatabase()
	})
	t.Run("Should return empty key because return not found records", func(t *testing.T) {
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)

		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, errorsEnum.ErrNotFoundRecords, nil))
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("GetConnection").Return(conn)

		c := NewExpiredKeys(mockRead, mockWrite)
		c.RemoveKeysExpiredFromDatabase()
	})
	t.Run("Should return keys but return errors on delete from database", func(t *testing.T) {
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)

		mockWrite := &relational.MockWrite{}
		mockWrite.On("DeleteByQuery").Return(response.NewResponse(0, errors.New("test"), nil))
		mockWrite.On("GetConnection").Return(conn)
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(1, nil, &[]cache.Cache{{Value: []byte("test"), Key: "key"}}))
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("GetConnection").Return(conn)

		c := NewExpiredKeys(mockRead, mockWrite)
		c.RemoveKeysExpiredFromDatabase()
	})
}
