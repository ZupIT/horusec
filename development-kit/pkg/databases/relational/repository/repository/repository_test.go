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

package repository

import (
	"errors"
	"os"
	"testing"
	"time"

	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestMock(t *testing.T) {
	m := &Mock{}
	m.On("Create").Return(nil)
	m.On("Update").Return(&accountEntities.Repository{}, nil)
	m.On("Get").Return(&accountEntities.Repository{}, nil)
	m.On("List").Return(&[]accountEntities.RepositoryResponse{}, nil)
	m.On("Delete").Return(nil)
	m.On("GetAllAccountsInRepository").Return(&[]roles.AccountRole{}, nil)
	m.On("GetByName").Return(&accountEntities.Repository{}, nil)
	m.On("GetAccountCompanyRole").Return(&roles.AccountCompany{}, nil)
	err := m.Create(&accountEntities.Repository{}, nil)
	assert.NoError(t, err)
	_, err = m.Update(uuid.New(), &accountEntities.Repository{})
	assert.NoError(t, err)
	_, err = m.Get(uuid.New())
	assert.NoError(t, err)
	_, err = m.List(uuid.New(), uuid.New())
	assert.NoError(t, err)
	err = m.Delete(uuid.New())
	assert.NoError(t, err)
	_, err = m.GetAllAccountsInRepository(uuid.New())
	assert.NoError(t, err)
	_, err = m.GetByName(uuid.New(), "")
	assert.NoError(t, err)
	_, err = m.GetAccountCompanyRole(uuid.New(), uuid.New())
	assert.NoError(t, err)
}

func TestCreateRepository(t *testing.T) {
	t.Run("should create repository without errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp)

		respFind := &response.Response{}
		respFind.SetError(errorsEnums.ErrNotFoundRecords)
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewRepository(mockRead, mockWrite)

		err := repository.Create(&accountEntities.Repository{}, mockWrite)
		assert.NoError(t, err)
	})

	t.Run("should return error name already in use", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp)

		respFind := &response.Response{}
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewRepository(mockRead, mockWrite)

		err := repository.Create(&accountEntities.Repository{}, mockWrite)
		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorRepositoryNameAlreadyInUse, err)
	})

	t.Run("should return generic error from get", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp)

		respFind := &response.Response{}
		respFind.SetError(errors.New("test"))
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewRepository(mockRead, mockWrite)

		err := repository.Create(&accountEntities.Repository{}, mockWrite)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})
}

func TestUpdateRepository(t *testing.T) {
	t.Run("should update with no errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Return(resp.SetData(&accountEntities.Repository{}))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewRepository(mockRead, mockWrite)

		_, err := repository.Update(uuid.New(), &accountEntities.Repository{})
		assert.NoError(t, err)
	})

	t.Run("should return not found records errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errorsEnums.ErrNotFoundRecords))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewRepository(mockRead, mockWrite)

		_, err := repository.Update(uuid.New(), &accountEntities.Repository{})
		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrNotFoundRecords, err)
	})
}

func TestList(t *testing.T) {
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

	repository := &accountEntities.Repository{
		RepositoryID: uuid.New(),
		CompanyID:    company.CompanyID,
		Name:         "test",
		CreatedAt:    time.Now(),
	}

	accountCompany := &roles.AccountCompany{
		AccountID: account.AccountID,
		CompanyID: company.CompanyID,
		Role:      rolesEnum.Admin,
		CreatedAt: time.Now(),
	}

	accountRepository := &roles.AccountRepository{
		AccountID:    account.AccountID,
		CompanyID:    company.CompanyID,
		RepositoryID: repository.RepositoryID,
		Role:         rolesEnum.Admin,
		CreatedAt:    time.Now(),
	}

	databaseWrite.SetLogMode(true)
	databaseWrite.GetConnection().Table(account.GetTable()).AutoMigrate(account)
	databaseWrite.GetConnection().Table(repository.GetTable()).AutoMigrate(repository)
	databaseWrite.GetConnection().Table(company.GetTable()).AutoMigrate(company)
	databaseWrite.GetConnection().Table(accountRepository.GetTable()).AutoMigrate(accountRepository)
	databaseWrite.GetConnection().Table(accountCompany.GetTable()).AutoMigrate(accountCompany)

	resp := databaseWrite.Create(account, account.GetTable())
	assert.NoError(t, resp.GetError())
	resp = databaseWrite.Create(company, company.GetTable())
	assert.NoError(t, resp.GetError())
	resp = databaseWrite.Create(repository, repository.GetTable())
	assert.NoError(t, resp.GetError())
	resp = databaseWrite.Create(accountRepository, accountRepository.GetTable())
	assert.NoError(t, resp.GetError())
	resp = databaseWrite.Create(accountCompany, accountCompany.GetTable())
	assert.NoError(t, resp.GetError())

	t.Run("should get repositories from account relation", func(t *testing.T) {
		repositoryRepo := NewRepository(databaseRead, databaseWrite)

		retrievedRepositories, err := repositoryRepo.List(account.AccountID, company.CompanyID)

		assert.NoError(t, err)
		assert.NotEmpty(t, retrievedRepositories)
	})

	t.Run("should return empty when not found", func(t *testing.T) {
		repository := NewRepository(databaseRead, databaseWrite)

		retrievedCompanies, err := repository.List(account.AccountID, company.CompanyID)

		assert.NoError(t, err)
		assert.NotEmpty(t, retrievedCompanies)
	})
}

func TestDeleteRepository(t *testing.T) {
	t.Run("should success delete repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)

		repository := NewRepository(mockRead, mockWrite)

		err := repository.Delete(uuid.New())
		assert.NoError(t, err)
	})
}

func TestGetAllAccountsInRepository(t *testing.T) {
	t.Run("should get all accounts in a repository", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		repositoryID := uuid.New()
		accounts := &[]roles.AccountRole{{Email: "test@test.com", Username: "test", Role: "member"}}

		accountsResp := &response.Response{}
		mockRead.On("RawSQL").Return(accountsResp.SetData(accounts))

		repository := NewRepository(mockRead, mockWrite)

		result, err := repository.GetAllAccountsInRepository(repositoryID)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestListAllInCompanyByLdap(t *testing.T) {
	_ = os.Setenv(config.EnvRelationalDialect, "sqlite3")
	_ = os.Setenv(config.EnvRelationalURI, "tmp.db")
	_ = os.Setenv(config.EnvRelationalLogMode, "false")

	databaseWrite := adapter.NewRepositoryWrite()
	databaseRead := adapter.NewRepositoryRead()

	company := &accountEntities.Company{
		CompanyID:   uuid.New(),
		Name:        "test",
		Description: "test",
		CreatedAt:   time.Now(),
	}

	repository := &accountEntities.Repository{
		RepositoryID: uuid.New(),
		CompanyID:    company.CompanyID,
		Name:         "test",
		CreatedAt:    time.Now(),
		AuthzAdmin:   []string{"test"},
	}

	databaseWrite.SetLogMode(true)
	databaseWrite.GetConnection().Table(repository.GetTable()).AutoMigrate(repository)
	databaseWrite.GetConnection().Table(company.GetTable()).AutoMigrate(company)

	resp := databaseWrite.Create(company, company.GetTable())
	assert.NoError(t, resp.GetError())
	resp = databaseWrite.Create(repository, repository.GetTable())

	t.Run("should get repositories from account relation", func(t *testing.T) {
		repositoryRepo := NewRepository(databaseRead, databaseWrite)

		retrievedRepositories, err := repositoryRepo.ListAllInCompanyByLdap(company.CompanyID, []string{"test"})

		assert.Error(t, err)
		assert.NotNil(t, retrievedRepositories)
	})
}
