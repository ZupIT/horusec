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

package roles

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestValidateRepository(t *testing.T) {
	t.Run("should return no error when valid account repository", func(t *testing.T) {
		accountRepository := &AccountRepository{
			AccountID:    uuid.New(),
			RepositoryID: uuid.New(),
			Role:         "admin",
		}

		assert.NoError(t, accountRepository.Validate())
	})

	t.Run("should return error when invalid account repository", func(t *testing.T) {
		accountRepository := &AccountRepository{}
		assert.Error(t, accountRepository.Validate())
	})
}

func TestSetCreateDataRepository(t *testing.T) {
	t.Run("should success set create data", func(t *testing.T) {
		accountRepository := &AccountRepository{}
		accountRepository.SetCreateData()
		assert.NotEmpty(t, accountRepository.CreatedAt)
		assert.NotEmpty(t, accountRepository.UpdatedAt)
	})
}

func TestSetUpdatedDataRepository(t *testing.T) {
	t.Run("should success set update data", func(t *testing.T) {
		accountRepository := &AccountRepository{}
		accountRepository.SetUpdateData(account.Admin)
		assert.NotEmpty(t, accountRepository.UpdatedAt)
	})
}

func TestGetTableRepository(t *testing.T) {
	t.Run("should success set update data", func(t *testing.T) {
		accountRepository := &AccountRepository{}
		assert.Equal(t, "account_repository", accountRepository.GetTable())
	})
}

func TestSetRepositoryAndAccountID(t *testing.T) {
	t.Run("should success set repository and account  id", func(t *testing.T) {
		accountRepository := &AccountRepository{}
		accountRepository.SetRepositoryAndAccountID(uuid.New(), uuid.New())
		assert.NotEqual(t, uuid.UUID{}, accountRepository.RepositoryID)
		assert.NotEqual(t, uuid.UUID{}, accountRepository.AccountID)
	})
}

func TestIsNotSupervisorOrAdmin(t *testing.T) {
	t.Run("should return true when its not admin or supervisor", func(t *testing.T) {
		accountRepository := &AccountRepository{Role: "member"}
		assert.True(t, accountRepository.IsNotSupervisorOrAdmin())
	})

	t.Run("should return false when is admin or supervisor", func(t *testing.T) {
		accountRepository := &AccountRepository{Role: "admin"}
		assert.False(t, accountRepository.IsNotSupervisorOrAdmin())

		accountRepository = &AccountRepository{Role: "supervisor"}
		assert.False(t, accountRepository.IsNotSupervisorOrAdmin())
	})
}

func TestIsNotAdminRepository(t *testing.T) {
	t.Run("should return true when its not admin", func(t *testing.T) {
		accountRepository := &AccountRepository{Role: "member"}
		assert.True(t, accountRepository.IsNotAdmin())
	})

	t.Run("should return false when is admin ", func(t *testing.T) {
		accountRepository := &AccountRepository{Role: "admin"}
		assert.False(t, accountRepository.IsNotAdmin())
	})
}
