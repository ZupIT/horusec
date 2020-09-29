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

	"github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestInviteUserToAccountRepository(t *testing.T) {
	t.Run("should success parse to account repository", func(t *testing.T) {
		inviteUser := InviteUser{
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
			Role:         account.Admin,
			Email:        "test@test.com",
		}

		accountRepository := inviteUser.ToAccountRepository(uuid.New())
		assert.NotNil(t, accountRepository)
		assert.NotEmpty(t, accountRepository)
	})
}

func TestSetInviteUserData(t *testing.T) {
	t.Run("should success parse to account repository", func(t *testing.T) {
		inviteUser := InviteUser{
			Role:  account.Admin,
			Email: "test@test.com",
		}

		inviteUser.SetInviteUserRepositoryAndCompanyID(uuid.New(), uuid.New())
		assert.NotEmpty(t, inviteUser.RepositoryID)
		assert.NotEmpty(t, inviteUser.CompanyID)
	})
}

func TestSetInviteUserCompanyID(t *testing.T) {
	t.Run("should success set company id", func(t *testing.T) {
		inviteUser := InviteUser{
			Role:  account.Admin,
			Email: "test@test.com",
		}

		inviteUser.SetInviteUserCompanyID(uuid.New())
		assert.NotEmpty(t, inviteUser.CompanyID)
	})
}
