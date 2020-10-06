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
	"time"

	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
)

type AccountRepository struct {
	RepositoryID uuid.UUID         `json:"repositoryID" swaggerignore:"true"`
	AccountID    uuid.UUID         `json:"accountID" swaggerignore:"true"`
	CompanyID    uuid.UUID         `json:"companyID" swaggerignore:"true"`
	Role         accountEnums.Role `json:"role"`
	CreatedAt    time.Time         `json:"createdAt" swaggerignore:"true"`
	UpdatedAt    time.Time         `json:"updatedAt" swaggerignore:"true"`
}

func (a *AccountRepository) Validate() error {
	return validation.ValidateStruct(a,
		validation.Field(&a.RepositoryID, validation.Required, is.UUID),
		validation.Field(&a.AccountID, validation.Required, is.UUID),
		validation.Field(&a.Role, validation.In(accountEnums.Admin,
			accountEnums.Member, accountEnums.Supervisor), validation.Required),
	)
}

func (a *AccountRepository) SetCreateData() *AccountRepository {
	a.CreatedAt = time.Now()
	a.UpdatedAt = time.Now()
	return a
}

func (a *AccountRepository) SetUpdateData(role accountEnums.Role) *AccountRepository {
	a.UpdatedAt = time.Now()
	a.Role = role
	return a
}

func (a *AccountRepository) GetTable() string {
	return "account_repository"
}

func (a *AccountRepository) SetRepositoryAndAccountID(repositoryID, accountID uuid.UUID) *AccountRepository {
	a.RepositoryID = repositoryID
	a.AccountID = accountID
	return a
}
