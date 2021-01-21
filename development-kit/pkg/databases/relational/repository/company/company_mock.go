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
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) Create(company *accountEntities.Company, tx SQL.InterfaceWrite) (*accountEntities.Company, error) {
	args := m.MethodCalled("Create")
	return args.Get(0).(*accountEntities.Company), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) Update(companyID uuid.UUID, data *accountEntities.Company) (*accountEntities.Company, error) {
	args := m.MethodCalled("Update")
	return args.Get(0).(*accountEntities.Company), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetByID(companyID uuid.UUID) (*accountEntities.Company, error) {
	args := m.MethodCalled("Update")
	return args.Get(0).(*accountEntities.Company), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetAllOfAccount(accountID uuid.UUID) (*[]accountEntities.CompanyResponse, error) {
	args := m.MethodCalled("GetAllOfAccount")
	return args.Get(0).(*[]accountEntities.CompanyResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) Delete(companyID uuid.UUID) error {
	args := m.MethodCalled("Delete")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) GetAllAccountsInCompany(companyID uuid.UUID) (*[]roles.AccountRole, error) {
	args := m.MethodCalled("GetAllAccountsInCompany")
	return args.Get(0).(*[]roles.AccountRole), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetAllOfAccountLdap(permissions []string) (*[]accountEntities.CompanyResponse, error) {
	args := m.MethodCalled("GetAllOfAccountLdap")
	return args.Get(0).(*[]accountEntities.CompanyResponse), mockUtils.ReturnNilOrError(args, 1)
}
