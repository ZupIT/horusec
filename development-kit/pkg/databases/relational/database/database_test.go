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
	"os"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/entities"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("tmp")
	_ = os.MkdirAll("tmp", 0750)
	m.Run()
	_ = os.RemoveAll("tmp")
}

func MockTableEntity() entities.Test {
	return entities.Test{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Name:      uuid.New().String(),
	}
}

func GetTableAndConnectionRead(logMode bool) (*entities.Test, relational.InterfaceRead) {
	tableTest := &entities.Test{}
	connection := NewRelationalRead(config.NewConfig().Dialect, config.NewConfig().URI, config.NewConfig().LogMode)
	connection.SetLogMode(logMode)
	_ = connection.GetConnection().Table(tableTest.TableName()).AutoMigrate(tableTest)
	return tableTest, connection
}

func GetTableAndConnectionWrite(logMode bool) (*entities.Test, relational.InterfaceWrite) {
	tableTest := &entities.Test{}
	connection := NewRelationalWrite(config.NewConfig().Dialect, config.NewConfig().URI, config.NewConfig().LogMode)
	connection.SetLogMode(logMode)
	_ = connection.GetConnection().Table(tableTest.TableName()).AutoMigrate(tableTest)
	return tableTest, connection
}

func TestRelational_GetConnection(t *testing.T) {
	t.Run("Should not return nil in connection IN READ", func(t *testing.T) {
		_, conn := GetTableAndConnectionRead(false)
		assert.NotNil(t, conn.GetConnection())
	})
	t.Run("Should not return nil in connection IN WRITE", func(t *testing.T) {
		_, conn := GetTableAndConnectionWrite(false)
		assert.NotNil(t, conn.GetConnection())
	})
}

func TestNewRelationalRead(t *testing.T) {
	t.Run("Should return panic when connection is wrong", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "some wrong dialect")
		assert.Panics(t, func() {
			GetTableAndConnectionRead(false)
		})
	})
}

func TestNewRelationalWrite(t *testing.T) {
	t.Run("Should return panic when connection is wrong", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "some wrong dialect")
		assert.Panics(t, func() {
			GetTableAndConnectionWrite(false)
		})
	})
}

func TestRelational_IsAvailable(t *testing.T) {
	t.Run("Should return true when check isAvailable", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		_, conn := GetTableAndConnectionRead(false)
		assert.True(t, conn.IsAvailable())
	})
	t.Run("Should return false when check isAvailable", func(t *testing.T) {
		fakeConn := &Relational{}
		assert.False(t, fakeConn.IsAvailable())
	})
}

func TestRelational_StartTransaction(t *testing.T) {
	t.Run("Should Create data with transaction without error", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")

		entityToCreate := MockTableEntity()

		table, connWrite := GetTableAndConnectionWrite(true)
		_, connRead := GetTableAndConnectionRead(true)

		tx := connWrite.StartTransaction()
		responseCreate := tx.Create(&entityToCreate, table.TableName())
		assert.NoError(t, responseCreate.GetError())
		assert.NoError(t, tx.CommitTransaction().GetError())

		responseFindAll := connRead.Find(&[]entities.Test{}, connRead.GetConnection().Where(map[string]interface{}{"id": entityToCreate.ID.String()}), table.TableName())
		assert.NoError(t, responseFindAll.GetError())
		dataFounded := responseFindAll.GetData().(*[]entities.Test)
		assert.NotEqual(t, dataFounded, &[]entities.Test{})
		assert.Len(t, *dataFounded, 1)
	})
}

func TestRelational_StartTransactionWithNotTransactionOperation(t *testing.T) {
	t.Run("Should not affect another operations", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")

		entityToCreate := MockTableEntity()

		table, connWrite := GetTableAndConnectionWrite(false)
		_, connRead := GetTableAndConnectionRead(false)

		tx := connWrite.StartTransaction()
		responseCreate := tx.Create(entityToCreate, table.TableName())
		assert.NoError(t, responseCreate.GetError())
		assert.NoError(t, tx.CommitTransaction().GetError())

		entityToCreateWithoutTransaction := MockTableEntity()
		reponseCreateNotTransaction := connWrite.Create(entityToCreateWithoutTransaction, table.TableName())
		assert.NoError(t, reponseCreateNotTransaction.GetError())

		filter := connRead.GetConnection().Where(map[string]interface{}{"id": entityToCreateWithoutTransaction.ID})
		responseFindAll := connRead.Find(&[]entities.Test{}, filter, table.TableName())
		assert.NoError(t, responseFindAll.GetError())
		dataFounded := responseFindAll.GetData().(*[]entities.Test)
		assert.NotEqual(t, dataFounded, &[]entities.Test{})
		assert.Len(t, *dataFounded, 1)
	})
}

func TestRelational_RollbackTransaction(t *testing.T) {
	t.Run("Should Create data with transaction and rollback data", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")

		entityToCreate := MockTableEntity()
		table, connWrite := GetTableAndConnectionWrite(false)
		_, connRead := GetTableAndConnectionRead(false)

		tx := connWrite.StartTransaction()
		responseCreate := tx.Create(entityToCreate, table.TableName())
		assert.NoError(t, responseCreate.GetError())
		assert.NoError(t, tx.RollbackTransaction().GetError())

		filter := connRead.GetConnection().Where(map[string]interface{}{"id": entityToCreate.ID})
		responseFindAll := connRead.Find(&[]entities.Test{}, filter, table.TableName())
		assert.Equal(t, EnumErrors.ErrNotFoundRecords, responseFindAll.GetError())
	})
}

func TestRelational_Create(t *testing.T) {
	t.Run("Should return error when connection is nil", func(t *testing.T) {
		fakeConn := &Relational{}
		assert.Equal(t, fakeConn.Create(nil, "").GetError(), EnumErrors.ErrDatabaseNotConnected)
	})
}

func TestRelational_FindAll(t *testing.T) {
	t.Run("Should return error when connection is nil", func(t *testing.T) {
		fakeConn := &Relational{}
		assert.Equal(t, fakeConn.Find(nil, nil, "").GetError(), EnumErrors.ErrDatabaseNotConnected)
	})
}

func TestRelational_FindOne(t *testing.T) {
	t.Run("Should return error when connection is nil", func(t *testing.T) {
		fakeConn := &Relational{}
		assert.Equal(t, fakeConn.Find(nil, nil, "").GetError(), EnumErrors.ErrDatabaseNotConnected)
	})
	t.Run("Should return error when table not exists ", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")

		table := MockTableEntity()
		_, connRead := GetTableAndConnectionRead(false)
		filter := connRead.GetConnection().Where(map[string]interface{}{"id": table.ID})
		responseFindOne := connRead.Find(&entities.Test{}, filter, "some other table")
		assert.Error(t, responseFindOne.GetError())
	})
	t.Run("Should create item and check if exists on database", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")

		entityToCreate := MockTableEntity()
		table, connWrite := GetTableAndConnectionWrite(false)
		responseCreate := connWrite.Create(entityToCreate, table.TableName())
		assert.NoError(t, responseCreate.GetError())

		_, connRead := GetTableAndConnectionRead(false)
		filter := connRead.GetConnection().Where(map[string]interface{}{"id": entityToCreate.ID})
		responseFindOne := connRead.Find(&entities.Test{}, filter, table.TableName())
		assert.NoError(t, responseFindOne.GetError())
		assert.NotEqual(t, responseFindOne.GetData().(*entities.Test), &entities.Test{})
	})
	t.Run("Should return not found when search item not exists on database", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		table := MockTableEntity()
		_, connRead := GetTableAndConnectionRead(false)
		filter := connRead.GetConnection().Where(map[string]interface{}{"id": table.ID})
		responseFindOne := connRead.Find(&entities.Test{}, filter, table.TableName())
		assert.Error(t, responseFindOne.GetError())
		assert.Equal(t, responseFindOne.GetError(), EnumErrors.ErrNotFoundRecords)
	})
}

func TestRelational_Update(t *testing.T) {
	t.Run("Should return error when connection is nil", func(t *testing.T) {
		fakeConn := &Relational{}
		assert.Equal(t, fakeConn.Update(nil, nil, "").GetError(), EnumErrors.ErrDatabaseNotConnected)
	})
	t.Run("Should update data with new values", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		table := MockTableEntity()
		_, connRead := GetTableAndConnectionRead(false)
		_, connWrite := GetTableAndConnectionWrite(false)
		responseCreate := connWrite.Create(table, table.TableName())
		assert.NoError(t, responseCreate.GetError())
		tableUpdated := MockTableEntity()
		tableUpdated.ID = table.ID
		responseUpdate := connWrite.Update(tableUpdated, map[string]interface{}{"id": tableUpdated.ID}, tableUpdated.TableName())
		assert.NoError(t, responseUpdate.GetError())
		filter := connRead.GetConnection().Where(map[string]interface{}{"id": tableUpdated.ID})
		responseFindOne := connRead.Find(&entities.Test{}, filter, table.TableName())
		assert.NoError(t, responseFindOne.GetError())
		tableFounded := responseFindOne.GetData().(*entities.Test)
		assert.NotEqual(t, tableFounded.Name, table.Name)
	})
}

func TestRelational_Delete(t *testing.T) {
	t.Run("Should return error when connection is nil", func(t *testing.T) {
		fakeConn := &Relational{}
		assert.Equal(t, fakeConn.Delete(nil, "").GetError(), EnumErrors.ErrDatabaseNotConnected)
	})
	t.Run("Should delete data without error", func(t *testing.T) {
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")

		table := MockTableEntity()
		_, connRead := GetTableAndConnectionRead(false)
		_, connWrite := GetTableAndConnectionWrite(false)
		responseCreate := connWrite.Create(table, table.TableName())
		assert.NoError(t, responseCreate.GetError())

		filter := connRead.GetConnection().Where(map[string]interface{}{"id": table.ID})
		responseFindOne := connRead.Find(&entities.Test{}, filter, table.TableName())
		assert.NoError(t, responseFindOne.GetError())
		assert.Equal(t, responseFindOne.GetData().(*entities.Test).Name, table.Name)

		responseUpdate := connWrite.Delete(map[string]interface{}{"id": table.ID}, table.TableName())
		assert.NoError(t, responseUpdate.GetError())

		responseFindOneAfterDelete := connRead.Find(&entities.Test{}, filter, table.TableName())
		assert.Error(t, responseFindOneAfterDelete.GetError())
		assert.Equal(t, responseFindOneAfterDelete.GetError(), EnumErrors.ErrNotFoundRecords)
	})
}

func TestIntegration(t *testing.T) {
	t.Run("Should create relation 1:1 and return expected data", func(t *testing.T) {
		mockUser := entities.User{
			ID:   uuid.New(),
			Name: uuid.New().String(),
		}
		mockCreditCards := entities.CreditCard{
			ID:     uuid.New(),
			Name:   "12345",
			UserID: mockUser.ID,
		}

		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		connWrite := NewRelationalWrite(config.NewConfig().Dialect, config.NewConfig().URI, config.NewConfig().LogMode)
		connRead := NewRelationalRead(config.NewConfig().Dialect, config.NewConfig().URI, config.NewConfig().LogMode)
		connWrite.SetLogMode(false)
		connRead.SetLogMode(false)

		founded := entities.CreditCard{}

		_ = connWrite.GetConnection().Table("users").AutoMigrate(&entities.User{})
		_ = connWrite.GetConnection().Table("credit_cards").AutoMigrate(&entities.CreditCard{})

		response := connWrite.Create(&mockUser, "users")
		assert.NoError(t, response.GetError())
		response = connWrite.Create(&mockCreditCards, "credit_cards")
		assert.NoError(t, response.GetError())

		query := connRead.GetConnection().Limit(1).Preload("User")
		assert.NoError(t, query.Error)
		responseFind := connRead.Find(&founded, query, "credit_cards")
		assert.NoError(t, responseFind.GetError())

		if responseFind.GetData() != nil {
			convertedData := responseFind.GetData().(*entities.CreditCard)
			assert.NotEqual(t, convertedData.ID, uuid.Nil)
			assert.NotEqual(t, convertedData.Name, "")
			assert.NotEqual(t, convertedData.UserID, uuid.Nil)
			assert.NotEqual(t, convertedData.User, nil)
			assert.NotEqual(t, convertedData.User.ID, uuid.Nil)
			assert.NotEqual(t, convertedData.User.Name, "")
		}
	})
	t.Run("Should create relation 1:N and return expected data", func(t *testing.T) {
		mockZoo := entities.Zoo{
			ID:   uuid.New(),
			Name: uuid.New().String(),
		}
		mockPet := entities.Pet{
			ID:    uuid.New(),
			Name:  "lion",
			ZooID: mockZoo.ID,
		}

		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		connWrite := NewRelationalWrite(config.NewConfig().Dialect, config.NewConfig().URI, config.NewConfig().LogMode)
		connRead := NewRelationalRead(config.NewConfig().Dialect, config.NewConfig().URI, config.NewConfig().LogMode)
		connWrite.SetLogMode(false)
		connRead.SetLogMode(false)

		founded := entities.Zoo{}
		_ = connWrite.GetConnection().Table("zoos").AutoMigrate(&entities.Zoo{})
		_ = connWrite.GetConnection().Table("pets").AutoMigrate(&entities.Pet{})

		response := connWrite.Create(&mockZoo, "zoos")
		assert.NoError(t, response.GetError())
		response = connWrite.Create(&mockPet, "pets")
		assert.NoError(t, response.GetError())

		query := connRead.GetConnection().Limit(1).Preload("Pet")
		assert.NoError(t, query.Error)
		responseFind := connRead.Find(&founded, query, "zoos")
		assert.NoError(t, responseFind.GetError())

		if responseFind.GetData() != nil {
			convertedData := responseFind.GetData().(*entities.Zoo)
			assert.NotEqual(t, convertedData.ID, uuid.Nil)
			assert.NotEqual(t, convertedData.Name, "")
			assert.NotEqual(t, convertedData.Pet, nil)
			assert.NotEqual(t, len(convertedData.Pet), 0)
			assert.NotEqual(t, convertedData.Pet[0].ID, uuid.Nil)
			assert.NotEqual(t, convertedData.Pet[0].Name, "")
			assert.NotEqual(t, convertedData.Pet[0].ZooID, uuid.Nil)
		}
	})
	t.Run("Should create relation N:N and return expected data", func(t *testing.T) {
		mockComputer := entities.Computer{
			ID:   uuid.New(),
			Name: uuid.New().String(),
		}
		mockLanguage := entities.Language{
			ID:   uuid.New(),
			Name: uuid.New().String(),
		}
		mockManyToMany := entities.ComputersLanguages{
			ComputerID: mockComputer.ID,
			LanguageID: mockLanguage.ID,
		}

		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")

		connWrite := NewRelationalWrite(config.NewConfig().Dialect, config.NewConfig().URI, config.NewConfig().LogMode)
		connWrite.SetLogMode(true)
		_ = connWrite.GetConnection().Table("computers").AutoMigrate(&entities.Computer{})
		_ = connWrite.GetConnection().Table("languages").AutoMigrate(&entities.Language{})
		_ = connWrite.GetConnection().Table("computers_languages").AutoMigrate(&entities.ComputersLanguages{})

		connRead := NewRelationalRead(config.NewConfig().Dialect, config.NewConfig().URI, config.NewConfig().LogMode)
		connRead.SetLogMode(true)

		response := connWrite.Create(&mockComputer, "computers")
		assert.NoError(t, response.GetError())
		response = connWrite.Create(&mockLanguage, "languages")
		assert.NoError(t, response.GetError())
		response = connWrite.Create(&mockManyToMany, "computers_languages")
		assert.NoError(t, response.GetError())

		founded := entities.Computer{}
		query := connRead.GetConnection().Limit(1).
			Preload("ComputersLanguages").
			Preload("ComputersLanguages.Language").
			Preload("ComputersLanguages.Computer")
		assert.NoError(t, query.Error)
		responseFind := connRead.Find(&founded, query, "computers")
		assert.NoError(t, responseFind.GetError())
		if responseFind.GetData() != nil {
			convertedData := responseFind.GetData().(*entities.Computer)
			assert.NotEqual(t, convertedData.ID, uuid.Nil)
			assert.NotEqual(t, convertedData.Name, "")
			assert.NotEqual(t, convertedData.ComputersLanguages, nil)
			assert.NotEqual(t, len(convertedData.ComputersLanguages), 0)
			assert.NotEqual(t, convertedData.ComputersLanguages[0].ComputerID, uuid.Nil)
			assert.NotEqual(t, convertedData.ComputersLanguages[0].LanguageID, uuid.Nil)
			assert.NotEqual(t, convertedData.ComputersLanguages[0].Language.ID, uuid.Nil)
			assert.NotEqual(t, convertedData.ComputersLanguages[0].Language.Name, "")
			assert.NotEqual(t, convertedData.ComputersLanguages[0].Computer.ID, uuid.Nil)
			assert.NotEqual(t, convertedData.ComputersLanguages[0].Computer.Name, "")
		}
	})
}
