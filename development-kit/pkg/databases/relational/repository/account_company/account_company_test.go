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

package accountcompany

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestGetAccountCompany(t *testing.T) {
	t.Run("should get data with no errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(&roles.AccountCompany{}))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewAccountCompanyRepository(mockRead, mockWrite)

		accountCompany, err := repository.GetAccountCompany(uuid.New(), uuid.New())
		assert.NoError(t, err)
		assert.NotNil(t, accountCompany)
	})
}

func TestCreateAccountCompany(t *testing.T) {
	t.Run("should return no errors when creating account repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp)

		repository := NewAccountCompanyRepository(mockRead, mockWrite)

		err := repository.CreateAccountCompany(uuid.New(), uuid.New(), rolesEnum.Admin, mockWrite)
		assert.NoError(t, err)
	})

	t.Run("should return error when something went wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp.SetError(errors.New("test")))

		repository := NewAccountCompanyRepository(mockRead, mockWrite)

		err := repository.CreateAccountCompany(uuid.New(), uuid.New(), rolesEnum.Admin, mockWrite)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})
}

func TestUpdateAccountCompany(t *testing.T) {
	t.Run("should success update account repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Return(resp.SetData(&roles.AccountCompany{}))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewAccountCompanyRepository(mockRead, mockWrite)

		err := repository.UpdateAccountCompany(&roles.AccountCompany{})
		assert.NoError(t, err)
	})

	t.Run("should return error when updating account repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Return(resp.SetError(errorsEnum.ErrNotFoundRecords))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		repository := NewAccountCompanyRepository(mockRead, mockWrite)

		err := repository.UpdateAccountCompany(&roles.AccountCompany{})
		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrNotFoundRecords, err)
	})
}

func TestDeleteAccountCompany(t *testing.T) {
	t.Run("should success delete account company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)

		repository := NewAccountCompanyRepository(mockRead, mockWrite)

		err := repository.DeleteAccountCompany(uuid.New(), uuid.New())
		assert.NoError(t, err)
	})
}
