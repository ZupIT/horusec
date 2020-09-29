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
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"

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
	t.Run("should get companies from account relation", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		account := &accountEntities.Account{}
		accountResp := &response.Response{}
		mockRead.On("First").Return(accountResp.SetData(account))

		companies := &[]accountEntities.Company{{Name: "test "}}
		companiesResp := &response.Response{}
		mockRead.On("Related").Return(companiesResp.SetData(companies))

		repository := NewCompanyRepository(mockRead, mockWrite)

		retrievedCompanies, err := repository.GetAllOfAccount(uuid.New())

		assert.NoError(t, err)
		assert.NotNil(t, retrievedCompanies)
		mockRead.AssertCalled(t, "First")
		mockRead.AssertCalled(t, "Related")
	})

	t.Run("should return an error when get model fails", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		accountResp := &response.Response{}
		mockRead.On("First").Return(accountResp.SetError(errors.New("test")))

		companies := &[]accountEntities.Company{{Name: "test "}}
		companiesResp := &response.Response{}
		mockRead.On("Related").Return(companiesResp.SetData(companies))

		repository := NewCompanyRepository(mockRead, mockWrite)

		retrievedCompanies, err := repository.GetAllOfAccount(uuid.New())

		assert.Error(t, err)
		assert.Nil(t, retrievedCompanies)
		mockRead.AssertCalled(t, "First")
		mockRead.AssertNotCalled(t, "Related")
	})

	t.Run("should return an error when related fails", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}

		account := &accountEntities.Account{}
		accountResp := &response.Response{}
		mockRead.On("First").Return(accountResp.SetData(account))

		companiesResp := &response.Response{}
		mockRead.On("Related").Return(companiesResp.SetError(errors.New("test")))

		repository := NewCompanyRepository(mockRead, mockWrite)

		retrievedCompanies, err := repository.GetAllOfAccount(uuid.New())

		assert.Error(t, err)
		assert.Nil(t, retrievedCompanies)
		mockRead.AssertCalled(t, "First")
		mockRead.AssertCalled(t, "Related")
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
