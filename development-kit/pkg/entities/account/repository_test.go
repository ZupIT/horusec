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

	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestRepositoryValidate(t *testing.T) {
	t.Run("validate should return an error when the struct is not valid", func(t *testing.T) {
		repository := &Repository{}
		assert.Error(t, repository.Validate())
	})

	t.Run("validate should return nil when the struct is valid", func(t *testing.T) {
		repository := &Repository{Name: "test", CompanyID: uuid.New()}
		assert.Nil(t, repository.Validate())
	})
}

func TestRepositoryGetTable(t *testing.T) {
	t.Run("should return the table name", func(t *testing.T) {
		repository := &Repository{}
		assert.Equal(t, "repositories", repository.GetTable())
	})
}

func TestToAccountRepository(t *testing.T) {
	t.Run("should success parse repository to account repository", func(t *testing.T) {
		repository := &Repository{RepositoryID: uuid.New()}
		assert.NotEmpty(t, repository.ToAccountRepository(rolesEnum.Admin, uuid.New()))
	})
}

func TestSetUpdateData(t *testing.T) {
	t.Run("should success set update data", func(t *testing.T) {
		repository := &Repository{RepositoryID: uuid.New()}
		repository.SetUpdateData("test", "test")
		assert.NotEmpty(t, repository)
		assert.Equal(t, "test", repository.Name)
		assert.Equal(t, "test", repository.Description)
	})
}

func TestSetCreateData(t *testing.T) {
	t.Run("should success set update data", func(t *testing.T) {
		repository := &Repository{RepositoryID: uuid.New()}
		repository.SetCreateData(uuid.New())
		assert.NotEmpty(t, repository)
	})
}

func TestToRepositoryResponse(t *testing.T) {
	t.Run("should success parse to repository response", func(t *testing.T) {
		company := &Repository{
			Name:        "test",
			Description: "test",
		}

		assert.NotEmpty(t, company.ToRepositoryResponse(rolesEnum.Admin))
	})
}
