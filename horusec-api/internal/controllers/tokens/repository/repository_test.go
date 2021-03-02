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
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	"os"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	_ "gorm.io/driver/sqlite" // Required in gorm usage
)

func TestNewController(t *testing.T) {
	t.Run("should create a new token repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		controller := NewController(mockRead, mockWrite)

		assert.NotNil(t, controller)
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

		controller := NewController(mockRead, mockWrite)

		newToken, err := controller.CreateTokenRepository(token)

		assert.NoError(t, err)
		assert.NotEmpty(t, newToken)
		mockWrite.AssertCalled(t, "Create")
	})

	t.Run("should return and error when Create functions return a response with error", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		token := &api.Token{
			Description: "1",
		}
		mockWrite.On("Create").Return(response.NewResponse(0, errors.New("error"), nil))

		controller := NewController(mockRead, mockWrite)

		newToken, err := controller.CreateTokenRepository(token)

		assert.Error(t, err)
		assert.Empty(t, newToken)
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

		controller := NewController(mockRead, mockWrite)

		err := controller.DeleteTokenRepository(uuid.New())

		assert.NoError(t, err)
		mockWrite.AssertCalled(t, "Delete")
	})

	t.Run("should fails on token delete", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		resp.SetError(errors.New("test"))
		mockWrite.On("Delete").Return(resp)

		controller := NewController(mockRead, mockWrite)

		err := controller.DeleteTokenRepository(uuid.New())

		assert.Error(t, err)
		mockWrite.AssertCalled(t, "Delete")
	})
}

func TestGetAllOfRepository(t *testing.T) {
	t.Run("should successfuly return repository tokens", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		resp.SetData(&[]api.Token{{Description: "some text"}})
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(resp)

		controller := NewController(mockRead, mockWrite)

		retrievedTokens, err := controller.GetAllTokenRepository(uuid.New())

		assert.NoError(t, err)
		assert.NotNil(t, retrievedTokens)
		mockRead.AssertCalled(t, "Find")
	})

	t.Run("should return an error when token retrive fails", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		resp.SetError(errors.New("test"))
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(resp)

		controller := NewController(mockRead, mockWrite)

		retrievedTokens, err := controller.GetAllTokenRepository(uuid.New())

		assert.Error(t, err)
		assert.Nil(t, retrievedTokens)
		mockRead.AssertCalled(t, "Find")
	})
}
