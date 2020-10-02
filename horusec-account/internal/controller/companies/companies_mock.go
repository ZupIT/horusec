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

package companies

import (
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) Create(accountID uuid.UUID, data *accountEntities.Company) (*accountEntities.Company, error) {
	args := m.MethodCalled("Create")
	return args.Get(0).(*accountEntities.Company), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) Update(companyID uuid.UUID, data *accountEntities.Company) (*accountEntities.Company, error) {
	args := m.MethodCalled("Update")
	return args.Get(0).(*accountEntities.Company), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) Get(companyID, accountID uuid.UUID) (*accountEntities.CompanyResponse, error) {
	args := m.MethodCalled("Get")
	return args.Get(0).(*accountEntities.CompanyResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) List(accountID uuid.UUID) (*[]accountEntities.CompanyResponse, error) {
	args := m.MethodCalled("List")
	return args.Get(0).(*[]accountEntities.CompanyResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) UpdateAccountCompany(role *roles.AccountCompany) error {
	args := m.MethodCalled("UpdateAccountCompany")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) InviteUser(inviteUser *accountEntities.InviteUser) error {
	args := m.MethodCalled("InviteUser")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) Delete(companyID uuid.UUID) error {
	args := m.MethodCalled("Delete")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) GetAllAccountsInCompany(companyID uuid.UUID) (*[]roles.AccountRole, error) {
	args := m.MethodCalled("Delete")
	return args.Get(0).(*[]roles.AccountRole), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) RemoveUser(removeUser *accountEntities.RemoveUser) error {
	args := m.MethodCalled("RemoveUser")
	return mockUtils.ReturnNilOrError(args, 0)
}
