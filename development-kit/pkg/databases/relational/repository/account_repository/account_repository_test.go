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

package accountrepository

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestGetAccountRepository(t *testing.T) {
	t.Run("should get data with no errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(&roles.AccountRepository{}))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewAccountRepositoryRepository(mockRead, mockWrite)

		accountRepository, err := repository.GetAccountRepository(uuid.New(), uuid.New())
		assert.NoError(t, err)
		assert.NotNil(t, accountRepository)
	})
}

func TestCreateAccountRepository(t *testing.T) {
	t.Run("should success create account repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp)

		repository := NewAccountRepositoryRepository(mockRead, mockWrite)

		err := repository.Create(&roles.AccountRepository{}, mockWrite)
		assert.NoError(t, err)
	})
}

func TestUpdateAccountRepository(t *testing.T) {
	t.Run("should success update account repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(&roles.AccountRepository{}))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)

		repository := NewAccountRepositoryRepository(mockRead, mockWrite)

		err := repository.UpdateAccountRepository(&roles.AccountRepository{})
		assert.NoError(t, err)
	})

	t.Run("should return error when getting account repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewAccountRepositoryRepository(mockRead, mockWrite)

		err := repository.UpdateAccountRepository(&roles.AccountRepository{})
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})
}

func TestDeleteAccountRepository(t *testing.T) {
	t.Run("should success delete account repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)

		repository := NewAccountRepositoryRepository(mockRead, mockWrite)

		err := repository.DeleteAccountRepository(uuid.New(), uuid.New())
		assert.NoError(t, err)
	})
}

func TestDeleteFromAllRepositories(t *testing.T) {
	t.Run("should success delete account repository by company id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)

		repository := NewAccountRepositoryRepository(mockRead, mockWrite)

		err := repository.DeleteFromAllRepositories(uuid.New(), uuid.New())
		assert.NoError(t, err)
	})
}

func TestGetOfAccount(t *testing.T) {
	t.Run("should success get all repository roles of an account", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(&[]roles.AccountRepository{{}}))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewAccountRepositoryRepository(mockRead, mockWrite)

		rolesFound, err := repository.GetOfAccount(uuid.New())

		assert.NoError(t, err)
		assert.NotNil(t, rolesFound)
	})

	t.Run("should not try to parse the nil pointer response", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewAccountRepositoryRepository(mockRead, mockWrite)

		rolesFound, _ := repository.GetOfAccount(uuid.New())

		assert.Nil(t, rolesFound)
	})
}
