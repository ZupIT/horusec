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

package accountcompany

import (
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/google/uuid"
)

type IAccountCompany interface {
	CreateAccountCompany(companyID, accountID uuid.UUID, role accountEnums.Role, tx SQL.InterfaceWrite) error
	GetAccountCompany(accountID, companyID uuid.UUID) (*roles.AccountCompany, error)
	UpdateAccountCompany(role *roles.AccountCompany) error
	DeleteAccountCompany(accountID, companyID uuid.UUID) error
}

type AccountCompany struct {
	databaseRead  SQL.InterfaceRead
	databaseWrite SQL.InterfaceWrite
}

func NewAccountCompanyRepository(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) IAccountCompany {
	return &AccountCompany{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
	}
}

func (a *AccountCompany) CreateAccountCompany(companyID, accountID uuid.UUID,
	role accountEnums.Role, tx SQL.InterfaceWrite) error {
	conn := a.databaseWrite
	if tx != nil {
		conn = tx
	}

	accountCompany := &roles.AccountCompany{
		CompanyID: companyID,
		AccountID: accountID,
		Role:      role,
	}

	response := conn.Create(accountCompany.SetCreateData(), accountCompany.GetTable())

	return response.GetError()
}

func (a *AccountCompany) GetAccountCompany(accountID, companyID uuid.UUID) (
	*roles.AccountCompany, error) {
	accountCompany := &roles.AccountCompany{}

	r := a.databaseRead.Find(&accountCompany,
		a.databaseRead.SetFilter(map[string]interface{}{"account_id": accountID, "company_id": companyID}),
		accountCompany.GetTable(),
	)

	return accountCompany, r.GetError()
}

func (a *AccountCompany) UpdateAccountCompany(accountCompany *roles.AccountCompany) error {
	toUpdate, err := a.GetAccountCompany(accountCompany.AccountID, accountCompany.CompanyID)
	if err != nil {
		return err
	}

	return a.databaseWrite.Update(toUpdate.SetUpdateData(accountCompany.Role),
		getAccountRoleFilter(toUpdate.AccountID, toUpdate.CompanyID), toUpdate.GetTable()).GetError()
}

func getAccountRoleFilter(accountID, companyID uuid.UUID) map[string]interface{} {
	return map[string]interface{}{"account_id": accountID, "company_id": companyID}
}

func (a *AccountCompany) DeleteAccountCompany(accountID, companyID uuid.UUID) error {
	return a.databaseWrite.Delete(getAccountRoleFilter(accountID, companyID), "account_company").GetError()
}
