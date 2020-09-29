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

package account

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestCreate(t *testing.T) {
	t.Run("should insert data with no errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp)

		repository := NewAccountRepository(mockRead, mockWrite)

		assert.NoError(t, repository.Create(&accountEntities.Account{}))
	})
}

func TestGetByAccountID(t *testing.T) {
	t.Run("should success get account with no errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp.SetData(&accountEntities.Account{}))

		repository := NewAccountRepository(mockRead, mockWrite)
		account, err := repository.GetByAccountID(uuid.New())

		assert.NoError(t, err)
		assert.NotNil(t, account)
	})
}

func TestGetByEmail(t *testing.T) {
	t.Run("should success get account by email with no errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp.SetData(&accountEntities.Account{}))

		repository := NewAccountRepository(mockRead, mockWrite)
		account, err := repository.GetByEmail("test@test.com")

		assert.NoError(t, err)
		assert.NotNil(t, account)
	})
}

func TestUpdate(t *testing.T) {
	t.Run("should update data with no errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)

		repository := NewAccountRepository(mockRead, mockWrite)

		assert.NoError(t, repository.Update(&accountEntities.Account{}))
	})
}
