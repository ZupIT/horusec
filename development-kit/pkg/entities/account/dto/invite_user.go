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

package dto

import (
	"encoding/json"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
)

type InviteUser struct {
	Role         accountEnums.Role `json:"role"`
	Email        string            `json:"email"`
	RepositoryID uuid.UUID         `json:"repositoryID" swaggerignore:"true"`
	CompanyID    uuid.UUID         `json:"companyID" swaggerignore:"true"`
}

func (i *InviteUser) Validate() error {
	return validation.ValidateStruct(i,
		validation.Field(&i.Email, validation.Length(1, 255), validation.Required, is.EmailFormat),
		validation.Field(&i.Role, validation.Length(1, 255),
			validation.In(accountEnums.Admin, accountEnums.Member, accountEnums.Supervisor), validation.Required),
		validation.Field(&i.RepositoryID, is.UUID),
		validation.Field(&i.CompanyID, is.UUID),
	)
}

func (i *InviteUser) ToAccountRepository(accountID uuid.UUID) *roles.AccountRepository {
	accountRepository := &roles.AccountRepository{
		RepositoryID: i.RepositoryID,
		CompanyID:    i.CompanyID,
		AccountID:    accountID,
		Role:         i.Role,
	}

	return accountRepository.SetCreateData()
}

func (i *InviteUser) SetInviteUserCompanyID(companyID uuid.UUID) *InviteUser {
	i.CompanyID = companyID
	return i
}

func (i *InviteUser) SetInviteUserRepositoryAndCompanyID(companyID, repositoryID uuid.UUID) *InviteUser {
	i.CompanyID = companyID
	i.RepositoryID = repositoryID
	return i
}

func (i *InviteUser) ToBytes() []byte {
	content, _ := json.Marshal(i)
	return content
}
