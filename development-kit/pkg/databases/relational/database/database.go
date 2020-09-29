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

package database

import (
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mssql"    // Required in gorm usage
	_ "github.com/jinzhu/gorm/dialects/mysql"    // Required in gorm usage
	_ "github.com/jinzhu/gorm/dialects/postgres" // Required in gorm usage
	_ "github.com/jinzhu/gorm/dialects/sqlite"   // Required in gorm usage
)

type Relational struct {
	connection *gorm.DB
}

func NewRelationalRead() relational.InterfaceRead {
	return constructor()
}

func NewRelationalWrite() relational.InterfaceWrite {
	return constructor()
}

func constructor() *Relational {
	db := &Relational{
		connection: nil,
	}
	result := db.Connect()
	if err := result.GetError(); err != nil {
		logger.LogPanic("connection with database has failed: ", err)
	}
	return db
}

func newRelationalForTransaction(conn *gorm.DB) relational.InterfaceWrite {
	return &Relational{
		connection: conn,
	}
}

func (r *Relational) Connect() *response.Response {
	configs := config.NewConfig()
	connection, err := gorm.Open(configs.Dialect, configs.URI)
	r.connection = connection
	r.SetLogMode(configs.LogMode)
	return response.NewResponse(0, err, r.connection)
}

func (r *Relational) GetConnection() *gorm.DB {
	return r.connection
}

func (r *Relational) SetLogMode(logMode bool) {
	if r.connection != nil {
		r.connection = r.connection.LogMode(logMode)
	}
}

func (r *Relational) StartTransaction() relational.InterfaceWrite {
	return newRelationalForTransaction(r.connection.Begin())
}

func (r *Relational) RollbackTransaction() *response.Response {
	return response.NewResponse(0, r.connection.Rollback().Error, nil)
}

func (r *Relational) CommitTransaction() *response.Response {
	return response.NewResponse(0, r.connection.Commit().Error, nil)
}

func (r *Relational) IsAvailable() bool {
	if r.connection != nil {
		return r.connection.DB().Ping() == nil
	}
	return false
}

func (r *Relational) Create(entity interface{}, tableName string) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}
	result := r.connection.Table(tableName).Create(entity)
	return response.NewResponse(int(result.RowsAffected), result.Error, entity)
}

func (r *Relational) CreateOrUpdate(
	entity interface{}, conditions map[string]interface{}, tableName string) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}
	result := r.connection.Table(tableName).Where(conditions).Save(entity)
	return response.NewResponse(int(result.RowsAffected), result.Error, entity)
}

func (r *Relational) Find(entity interface{}, query *gorm.DB, tableName string) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}
	result := query.Table(tableName).Find(entity)
	if result.Error != nil {
		if strings.EqualFold(result.Error.Error(), "record not found") {
			return response.NewResponse(int(result.RowsAffected), EnumErrors.ErrNotFoundRecords, nil)
		}
		return response.NewResponse(int(result.RowsAffected), result.Error, nil)
	}
	return response.NewResponse(int(result.RowsAffected), nil, entity)
}

func (r *Relational) Update(
	entity interface{}, conditions map[string]interface{}, tableName string) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}

	result := r.connection.Table(tableName).Where(conditions).Update(entity)

	return response.NewResponse(int(result.RowsAffected), result.Error, entity)
}

func (r *Relational) Delete(conditions map[string]interface{}, tableName string) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}

	result := r.connection.Table(tableName).Where(conditions).Delete(nil)

	return response.NewResponse(int(result.RowsAffected), result.Error, nil)
}

func (r *Relational) DeleteByQuery(query *gorm.DB, tableName string) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}

	result := query.Table(tableName).Delete(nil)

	return response.NewResponse(int(result.RowsAffected), result.Error, nil)
}

func (r *Relational) SetFilter(filter map[string]interface{}) *gorm.DB {
	return r.GetConnection().Where(filter)
}

func (r *Relational) First(out interface{}, where ...interface{}) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}

	result := r.connection.First(out, where...)
	if result.Error != nil {
		if strings.EqualFold(result.Error.Error(), "record not found") {
			return response.NewResponse(int(result.RowsAffected), EnumErrors.ErrNotFoundRecords, nil)
		}
		return response.NewResponse(int(result.RowsAffected), result.Error, nil)
	}

	return response.NewResponse(0, result.Error, out)
}

func (r *Relational) Related(
	model, related interface{}, filter map[string]interface{}, foreignKeys ...string) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}
	result := r.connection.Model(model)
	if filter != nil {
		result = result.Where(filter)
	}
	result = result.Related(related, foreignKeys...)
	return response.NewResponse(0, result.Error, related)
}

func (r *Relational) RawSQL(sql string, entity interface{}) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}

	result := r.connection.Raw(sql).Scan(entity)
	return response.NewResponse(int(result.RowsAffected), result.Error, entity)
}
