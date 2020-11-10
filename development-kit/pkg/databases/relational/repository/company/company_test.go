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

package company

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"os"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestCreateCompany(t *testing.T) {
	t.Run("should use current connection to create a company", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		company := &accountEntities.Company{}
		resp := &response.Response{}
		mockWrite.On("Create").Return(resp.SetData(company))

		repository := NewCompanyRepository(mockRead, mockWrite)

		createdCompany, err := repository.Create(company, nil)

		assert.NoError(t, err)
		assert.NotNil(t, createdCompany)
		mockWrite.AssertCalled(t, "Create")
	})

	t.Run("should return error and nil data", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		company := &accountEntities.Company{}

		resp := &response.Response{}
		resp.SetData(nil)
		resp.SetError(errors.New("test"))
		mockWrite.On("Create").Return(resp)

		repository := NewCompanyRepository(mockRead, mockWrite)

		createdCompany, err := repository.Create(company, nil)

		assert.Error(t, err)
		assert.Nil(t, createdCompany)
	})

	t.Run("should use transaction connection to create a company", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockTx := &relational.MockWrite{}

		company := &accountEntities.Company{}
		resp := &response.Response{}
		mockWrite.On("Create").Return(resp.SetData(company))
		mockTx.On("Create").Return(resp.SetData(company))

		repository := NewCompanyRepository(mockRead, mockWrite)

		createdCompany, err := repository.Create(company, mockTx)

		assert.NoError(t, err)
		assert.NotNil(t, createdCompany)
		mockWrite.AssertNotCalled(t, "Create")
		mockTx.AssertCalled(t, "Create")
	})
}

func TestUpdateCompany(t *testing.T) {
	t.Run("should call update method on database", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		company := &accountEntities.Company{}
		resp := &response.Response{}
		mockWrite.On("Update").Return(resp.SetData(company))

		repository := NewCompanyRepository(mockRead, mockWrite)

		updatedCompany, err := repository.Update(uuid.New(), company)

		assert.NoError(t, err)
		assert.NotNil(t, updatedCompany)
		mockWrite.AssertCalled(t, "Update")
	})

	t.Run("should return nil company and error", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		company := &accountEntities.Company{}
		resp := &response.Response{}
		resp.SetError(errors.New("test"))
		resp.SetData(nil)
		mockWrite.On("Update").Return(resp)

		repository := NewCompanyRepository(mockRead, mockWrite)

		updatedCompany, err := repository.Update(uuid.New(), company)

		assert.Error(t, err)
		assert.Nil(t, updatedCompany)
	})
}

func TestGetCompanyByID(t *testing.T) {
	t.Run("should call find method on database", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		company := &accountEntities.Company{}
		resp := &response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp.SetData(company))

		repository := NewCompanyRepository(mockRead, mockWrite)

		retrievedCompany, err := repository.GetByID(uuid.New())
		assert.NoError(t, err)
		assert.NotNil(t, retrievedCompany)
		mockRead.AssertCalled(t, "Find")
	})
}

func TestGetAllOfAccount(t *testing.T) {
	_ = os.Setenv(config.EnvRelationalDialect, "sqlite3")
	_ = os.Setenv(config.EnvRelationalURI, "tmp.db")
	_ = os.Setenv(config.EnvRelationalLogMode, "false")

	databaseWrite := adapter.NewRepositoryWrite()
	databaseRead := adapter.NewRepositoryRead()

	account := &authEntities.Account{
		Email:     "test@test.com",
		Username:  "test",
		CreatedAt: time.Now(),
		Password:  "test",
		AccountID: uuid.New(),
	}

	company := &accountEntities.Company{
		CompanyID:   uuid.New(),
		Name:        "test",
		Description: "test",
		CreatedAt:   time.Now(),
	}

	accountCompany := &roles.AccountCompany{
		AccountID: account.AccountID,
		CompanyID: company.CompanyID,
		Role:      rolesEnum.Admin,
		CreatedAt: time.Now(),
	}

	databaseWrite.SetLogMode(true)
	databaseWrite.GetConnection().Table(account.GetTable()).AutoMigrate(account)
	databaseWrite.GetConnection().Table(company.GetTable()).AutoMigrate(company)
	databaseWrite.GetConnection().Table(accountCompany.GetTable()).AutoMigrate(accountCompany)

	resp := databaseWrite.Create(account, account.GetTable())
	assert.NoError(t, resp.GetError())
	resp = databaseWrite.Create(company, company.GetTable())
	assert.NoError(t, resp.GetError())
	resp = databaseWrite.Create(accountCompany, accountCompany.GetTable())
	assert.NoError(t, resp.GetError())

	t.Run("should get companies from account relation", func(t *testing.T) {
		repo := NewCompanyRepository(databaseRead, databaseWrite)

		result, err := repo.GetAllOfAccount(account.AccountID)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("should return an error when get model fails", func(t *testing.T) {
		repo := NewCompanyRepository(databaseRead, databaseWrite)

		result, err := repo.GetAllOfAccount(uuid.UUID{})

		assert.NoError(t, err)
		assert.Empty(t, result)
	})
}

func TestDelete(t *testing.T) {
	t.Run("should success delete company", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)

		repository := NewCompanyRepository(mockRead, mockWrite)

		err := repository.Delete(uuid.New())
		assert.NoError(t, err)
	})
}

func TestGetAllAccountsInCompany(t *testing.T) {
	t.Run("should get all accounts in a company", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		companyID := uuid.New()
		accounts := &[]roles.AccountRole{{Email: "test@test.com", Username: "test", Role: "member"}}

		accountsResp := &response.Response{}
		mockRead.On("RawSQL").Return(accountsResp.SetData(accounts))

		repository := NewCompanyRepository(mockRead, mockWrite)

		result, err := repository.GetAllAccountsInCompany(companyID)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}
