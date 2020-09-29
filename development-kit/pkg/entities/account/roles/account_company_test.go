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

	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	t.Run("should return no error when valid account company", func(t *testing.T) {
		accountCompany := &AccountCompany{
			AccountID: uuid.New(),
			CompanyID: uuid.New(),
			Role:      "admin",
		}

		assert.NoError(t, accountCompany.Validate())
	})

	t.Run("should return error when invalid account company", func(t *testing.T) {
		accountCompany := &AccountCompany{}
		assert.Error(t, accountCompany.Validate())
	})
}

func TestSetCreateData(t *testing.T) {
	t.Run("should success set create data", func(t *testing.T) {
		accountCompany := &AccountCompany{}
		accountCompany.SetCreateData()
		assert.NotEmpty(t, accountCompany.CreatedAt)
		assert.NotEmpty(t, accountCompany.UpdatedAt)
	})
}

func TestSetUpdatedData(t *testing.T) {
	t.Run("should success set update data", func(t *testing.T) {
		accountCompany := &AccountCompany{}
		accountCompany.SetUpdateData(rolesEnum.Admin)
		assert.NotEmpty(t, accountCompany.UpdatedAt)
	})
}

func TestGetTable(t *testing.T) {
	t.Run("should success set update data", func(t *testing.T) {
		accountCompany := &AccountCompany{}
		assert.Equal(t, "account_company", accountCompany.GetTable())
	})
}

func TestSetCompanyAndAccountID(t *testing.T) {
	t.Run("should success set company and account id", func(t *testing.T) {
		accountCompany := &AccountCompany{}
		accountCompany.SetCompanyAndAccountID(uuid.New(), uuid.New())
		assert.NotEmpty(t, accountCompany.CompanyID)
		assert.NotEmpty(t, accountCompany.AccountID)
	})
}
