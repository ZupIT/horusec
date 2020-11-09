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
	"encoding/json"
	"time"

	"github.com/go-ozzo/ozzo-validation/v4/is"

	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
)

type AccountCompany struct {
	CompanyID uuid.UUID         `json:"companyID" swaggerignore:"true"`
	AccountID uuid.UUID         `json:"accountID" swaggerignore:"true"`
	Role      accountEnums.Role `json:"role"`
	CreatedAt time.Time         `json:"createdAt" swaggerignore:"true"`
	UpdatedAt time.Time         `json:"updatedAt" swaggerignore:"true"`
}

func (a *AccountCompany) Validate() error {
	return validation.ValidateStruct(a,
		validation.Field(&a.CompanyID, validation.Required, is.UUID),
		validation.Field(&a.AccountID, validation.Required, is.UUID),
		validation.Field(&a.Role, validation.In(accountEnums.Admin, accountEnums.Member), validation.Required),
	)
}

func (a *AccountCompany) SetCreateData() *AccountCompany {
	a.CreatedAt = time.Now()
	a.UpdatedAt = time.Now()
	return a
}

func (a *AccountCompany) SetUpdateData(role accountEnums.Role) *AccountCompany {
	a.Role = role
	a.UpdatedAt = time.Now()
	return a
}

func (a *AccountCompany) GetTable() string {
	return "account_company"
}

func (a *AccountCompany) SetCompanyAndAccountID(companyID, accountID uuid.UUID) *AccountCompany {
	a.CompanyID = companyID
	a.AccountID = accountID
	return a
}

func (a *AccountCompany) IsNotAdmin() bool {
	return a.Role != accountEnums.Admin
}

func (a *AccountCompany) ToBytes() []byte {
	content, _ := json.Marshal(a)
	return content
}
