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
	"errors"
	enumDialect "github.com/ZupIT/horusec/development-kit/pkg/enums/dialect"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	loggerGorm "gorm.io/gorm/logger"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	_ "gorm.io/driver/postgres" // Required in gorm usage
	_ "gorm.io/driver/sqlite"   // Required in gorm usage
	"gorm.io/gorm"
)

var (
	ErrDialectNotFound = errors.New("error on create connection with database dialect not found")
)

type Relational struct {
	connection *gorm.DB
}

func NewRelationalRead(dialect, uri string, logMode bool) relational.InterfaceRead {
	return constructor(dialect, uri, logMode)
}

func NewRelationalWrite(dialect, uri string, logMode bool) relational.InterfaceWrite {
	return constructor(dialect, uri, logMode)
}

func constructor(dialect, uri string, logMode bool) *Relational {
	db := &Relational{
		connection: nil,
	}
	result := db.Connect(dialect, uri, logMode)
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

func (r *Relational) Connect(dialect, uri string, logMode bool) *response.Response {
	connection, err := r.factoryConnection(dialect, uri)
	if err != nil {
		return response.NewResponse(0, err, nil)
	}
	r.connection = connection
	r.SetLogMode(logMode)
	return response.NewResponse(0, err, r.connection)
}

func (r *Relational) factoryConnection(dialect, uri string) (*gorm.DB, error) {
	switch dialect {
	case enumDialect.Postgres.ToString():
		return gorm.Open(postgres.Open(uri), &gorm.Config{})
	case enumDialect.SQLite.ToString():
		return gorm.Open(sqlite.Open(uri), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
		})
	default:
		return nil, ErrDialectNotFound
	}
}

func (r *Relational) GetConnection() *gorm.DB {
	return r.connection
}

func (r *Relational) SetLogMode(logMode bool) {
	if r.connection != nil {
		if logMode {
			r.connection.Logger = r.connection.Logger.LogMode(loggerGorm.Info)
		} else {
			r.connection.Logger = r.connection.Logger.LogMode(loggerGorm.Error)
		}
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
		database, err := r.connection.DB()
		if err != nil {
			logger.LogError("Error on get database to ping", err)
			return false
		}
		return database.Ping() == nil
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
	if result.RowsAffected == 0 {
		return response.NewResponse(int(result.RowsAffected), EnumErrors.ErrNotFoundRecords, nil)
	}
	return response.NewResponse(int(result.RowsAffected), nil, entity)
}

func (r *Relational) Update(
	entity interface{}, conditions map[string]interface{}, tableName string) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}

	result := r.connection.Table(tableName).Where(conditions).Updates(entity)

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

func (r *Relational) First(out interface{}, tableName string, where ...interface{}) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}

	result := r.connection.Table(tableName).First(out, where...)
	if result.Error != nil {
		if strings.EqualFold(result.Error.Error(), "record not found") {
			return response.NewResponse(int(result.RowsAffected), EnumErrors.ErrNotFoundRecords, nil)
		}
		return response.NewResponse(int(result.RowsAffected), result.Error, nil)
	}

	return response.NewResponse(0, result.Error, out)
}

func (r *Relational) RawSQL(sql string, entity interface{}) *response.Response {
	if r.connection == nil {
		return response.NewResponse(0, EnumErrors.ErrDatabaseNotConnected, nil)
	}

	result := r.connection.Raw(sql).Scan(entity)
	return response.NewResponse(int(result.RowsAffected), result.Error, entity)
}
