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

package company

import (
	"fmt"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	"github.com/google/uuid"
)

type ICompanyRepository interface {
	Create(company *accountEntities.Company, tx SQL.InterfaceWrite) (*accountEntities.Company, error)
	Update(companyID uuid.UUID, data *accountEntities.Company) (*accountEntities.Company, error)
	GetByID(companyID uuid.UUID) (*accountEntities.Company, error)
	GetAllOfAccount(accountID uuid.UUID) (*[]accountEntities.CompanyResponse, error)
	Delete(companyID uuid.UUID) error
	GetAllAccountsInCompany(companyID uuid.UUID) (*[]roles.AccountRole, error)
}

type Repository struct {
	databaseRead  SQL.InterfaceRead
	databaseWrite SQL.InterfaceWrite
}

func NewCompanyRepository(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) ICompanyRepository {
	return &Repository{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
	}
}

func (r *Repository) Create(
	company *accountEntities.Company, tx SQL.InterfaceWrite) (*accountEntities.Company, error) {
	conn := r.databaseWrite
	if tx != nil {
		conn = tx
	}

	response := conn.Create(company.SetCreateData(), company.GetTable())

	if response.GetData() == nil {
		return nil, response.GetError()
	}

	return response.GetData().(*accountEntities.Company), response.GetError()
}

func (r *Repository) Update(
	companyID uuid.UUID, data *accountEntities.Company) (*accountEntities.Company, error) {
	response := r.databaseWrite.Update(
		data.SetUpdateData(),
		getCompanyByIDFilter(companyID),
		data.GetTable(),
	)

	if response.GetData() == nil {
		return nil, response.GetError()
	}

	return response.GetData().(*accountEntities.Company), response.GetError()
}

func (r *Repository) GetByID(companyID uuid.UUID) (*accountEntities.Company, error) {
	company := &accountEntities.Company{}
	response := r.databaseRead.Find(company,
		r.databaseRead.SetFilter(getCompanyByIDFilter(companyID)), company.GetTable())

	return company, response.GetError()
}

func (r *Repository) GetAllOfAccount(accountID uuid.UUID) (*[]accountEntities.CompanyResponse, error) {
	companies := &[]accountEntities.CompanyResponse{}

	query := r.databaseRead.
		GetConnection().
		Select(
			"comp.company_id, comp.name, comp.description, accountComp.role,"+
				" comp.authz_admin, comp.authz_member, comp.created_at, comp.updated_at",
		).
		Table("companies AS comp").
		Joins("JOIN account_company AS accountComp ON accountComp.company_id = comp.company_id"+
			" AND accountComp.account_id = ?", accountID).
		Where("accountComp.account_id = ?", accountID).
		Find(&companies)

	return companies, query.Error
}

func getCompanyByIDFilter(companyID uuid.UUID) map[string]interface{} {
	return map[string]interface{}{"company_id": companyID}
}

func (r *Repository) Delete(companyID uuid.UUID) error {
	return r.databaseWrite.Delete(getCompanyByIDFilter(companyID), "companies").GetError()
}

//nolint
func (r *Repository) GetAllAccountsInCompany(companyID uuid.UUID) (*[]roles.AccountRole, error) {
	accounts := &[]roles.AccountRole{}

	query := fmt.Sprintf(`SELECT
		"email", "username", "role", "accounts"."account_id"
		FROM "accounts"
		INNER JOIN "account_company"
		ON "account_company"."account_id" = "accounts"."account_id"
		WHERE ("account_company"."company_id" IN ('%s'))
	`, companyID)

	response := r.databaseRead.RawSQL(query, accounts)
	return accounts, response.GetError()
}
