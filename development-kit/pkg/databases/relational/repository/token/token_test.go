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

package token

import (
	"errors"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"github.com/jinzhu/gorm"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewTokenRepository(t *testing.T) {
	t.Run("should create a new token repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		repository := NewTokenRepository(mockRead, mockWrite)

		assert.NotNil(t, repository)
	})
}

func TestCreate(t *testing.T) {
	t.Run("should successfuly call database Create function", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		token := &api.Token{}
		resp := &response.Response{}
		resp.SetData(token)
		mockWrite.On("Create").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		newToken, err := repository.Create(token)

		assert.NoError(t, err)
		assert.Equal(t, newToken, token)
		mockWrite.AssertCalled(t, "Create")
	})

	t.Run("should return nil token when the conversion fails", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		token := &api.Token{}
		resp := &response.Response{}
		resp.SetData(nil)
		mockWrite.On("Create").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		newToken, err := repository.Create(token)

		assert.NoError(t, err)
		assert.Nil(t, newToken)
		mockWrite.AssertCalled(t, "Create")
	})

	t.Run("should return and error when Create functions return a response with error", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		token := &api.Token{}
		resp := &response.Response{}
		resp.SetError(errors.New("test"))
		mockWrite.On("Create").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		newToken, err := repository.Create(token)

		assert.Error(t, err)
		assert.Nil(t, newToken)
		mockWrite.AssertCalled(t, "Create")
	})
}

func TestDelete(t *testing.T) {
	t.Run("should successfuly delete a token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		resp.SetError(nil)
		resp.SetRowsAffected(1)
		mockWrite.On("Delete").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		err := repository.Delete(uuid.New())

		assert.NoError(t, err)
		mockWrite.AssertCalled(t, "Delete")
	})

	t.Run("should return an error when delete fails", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		resp.SetError(errors.New("test"))
		mockWrite.On("Delete").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		err := repository.Delete(uuid.New())

		assert.Error(t, err)
		mockWrite.AssertCalled(t, "Delete")
	})
	t.Run("should return an error when delete fails", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		err := repository.Delete(uuid.New())

		assert.Error(t, err)
		mockWrite.AssertCalled(t, "Delete")
	})
}

func TestGetByValue(t *testing.T) {
	t.Run("should successfully call database Find function", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		token := &api.Token{}
		resp := &response.Response{}
		resp.SetData(token)
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		retrievedToken, err := repository.GetByValue("test")

		assert.NoError(t, err)
		assert.Equal(t, retrievedToken, token)
		mockRead.AssertCalled(t, "Find")
	})

	t.Run("should return nil token when the conversion fails", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		resp.SetData(nil)
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		retrievedToken, err := repository.GetByValue("test")

		assert.NoError(t, err)
		assert.Nil(t, retrievedToken)
		mockRead.AssertCalled(t, "Find")
	})

	t.Run("should return and error when Find functions return a response with error", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		resp.SetError(errors.New("test"))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		retrievedToken, err := repository.GetByValue("test")

		assert.Error(t, err)
		assert.Nil(t, retrievedToken)
		mockRead.AssertCalled(t, "Find")
	})
}

func TestGetAllOfRepository(t *testing.T) {
	t.Run("should successfully call database Find function", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		repositoryID := uuid.New()
		tokenList := &[]api.Token{
			{
				TokenID:      uuid.New(),
				Description:  "test",
				RepositoryID: &repositoryID,
				CompanyID:    uuid.New(),
				SuffixValue:  "test",
				Value:        "test",
				CreatedAt:    time.Now(),
				ExpiresAt:    time.Now(),
			},
			{
				TokenID:      uuid.New(),
				Description:  "test",
				RepositoryID: &repositoryID,
				CompanyID:    uuid.New(),
				SuffixValue:  "test",
				Value:        "test",
				CreatedAt:    time.Now(),
				ExpiresAt:    time.Now(),
			},
		}
		resp := &response.Response{}
		resp.SetData(tokenList)

		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		_, err := repository.GetAllOfRepository(uuid.New())

		assert.NoError(t, err)
		mockRead.AssertCalled(t, "Find")
	})

	t.Run("should return nil token when the conversion fails", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		resp.SetData(nil)

		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		tokens, err := repository.GetAllOfRepository(uuid.New())

		assert.NoError(t, err)
		assert.Nil(t, tokens)
		mockRead.AssertCalled(t, "Find")
	})

	t.Run("should return and error when Find functions return a response with error", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		resp.SetError(errors.New("test"))

		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(resp)

		repository := NewTokenRepository(mockRead, mockWrite)

		tokens, err := repository.GetAllOfRepository(uuid.New())

		assert.Error(t, err)
		assert.Nil(t, tokens)
		mockRead.AssertCalled(t, "Find")
	})
}

func TestRepository_GetAllOfCompany(t *testing.T) {
	mockRead := &relational.MockRead{}
	mockWrite := &relational.MockWrite{}
	repositoryID := uuid.New()
	tokenList := &[]api.Token{
		{
			TokenID:      uuid.New(),
			Description:  "test",
			RepositoryID: &repositoryID,
			CompanyID:    uuid.New(),
			SuffixValue:  "test",
			Value:        "test",
			CreatedAt:    time.Now(),
			ExpiresAt:    time.Now(),
		},
		{
			TokenID:      uuid.New(),
			Description:  "test",
			RepositoryID: &repositoryID,
			CompanyID:    uuid.New(),
			SuffixValue:  "test",
			Value:        "test",
			CreatedAt:    time.Now(),
			ExpiresAt:    time.Now(),
		},
	}
	resp := &response.Response{}
	resp.SetData(tokenList)

	mockRead.On("SetFilter").Return(&gorm.DB{})
	mockRead.On("Find").Return(resp)

	repository := NewTokenRepository(mockRead, mockWrite)

	_, err := repository.GetAllOfCompany(uuid.New())

	assert.NoError(t, err)
	mockRead.AssertCalled(t, "Find")
}
