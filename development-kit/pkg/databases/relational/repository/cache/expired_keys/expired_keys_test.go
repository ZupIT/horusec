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
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	"github.com/google/uuid"
	"os"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	_ "gorm.io/driver/sqlite" // Required in gorm usage
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("tmp")
	_ = os.MkdirAll("tmp", 0750)
	m.Run()
	_ = os.RemoveAll("tmp")
}

func TestExpiredKeys_RemoveKeysExpiredFromDatabase(t *testing.T) {
	t.Run("Should return empty key because return unexpected error on find keys", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, errors.New("some error"), nil))
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("GetConnection").Return(conn)

		c := NewExpiredKeys(mockRead, mockWrite)
		c.RemoveKeysExpiredFromDatabase()
	})
	t.Run("Should return empty key because return not found records", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, errorsEnum.ErrNotFoundRecords, nil))
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("GetConnection").Return(conn)

		c := NewExpiredKeys(mockRead, mockWrite)
		c.RemoveKeysExpiredFromDatabase()
	})
	t.Run("Should return keys but return errors on delete from database", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
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
