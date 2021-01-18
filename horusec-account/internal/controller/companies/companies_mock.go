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
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) Create(_ uuid.UUID, _ *accountEntities.Company) (*accountEntities.Company, error) {
	args := m.MethodCalled("Create")
	return args.Get(0).(*accountEntities.Company), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) Update(_ uuid.UUID, _ *accountEntities.Company) (*accountEntities.Company, error) {
	args := m.MethodCalled("Update")
	return args.Get(0).(*accountEntities.Company), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) Get(_, _ uuid.UUID) (*accountEntities.CompanyResponse, error) {
	args := m.MethodCalled("Get")
	return args.Get(0).(*accountEntities.CompanyResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) List(_ uuid.UUID, _ []string, _ authEnums.AuthorizationType) (*[]accountEntities.CompanyResponse, error) {
	args := m.MethodCalled("List")
	return args.Get(0).(*[]accountEntities.CompanyResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) UpdateAccountCompany(_ *roles.AccountCompany) error {
	args := m.MethodCalled("UpdateAccountCompany")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) InviteUser(_ *dto.InviteUser) error {
	args := m.MethodCalled("InviteUser")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) Delete(_ uuid.UUID) error {
	args := m.MethodCalled("Delete")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) GetAllAccountsInCompany(_ uuid.UUID) (*[]roles.AccountRole, error) {
	args := m.MethodCalled("GetAllAccountsInCompany")
	return args.Get(0).(*[]roles.AccountRole), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) RemoveUser(_ *dto.RemoveUser) error {
	args := m.MethodCalled("RemoveUser")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) GetAccountIDByEmail(_ string) (uuid.UUID, error) {
	args := m.MethodCalled("GetAccountIDByEmail")
	return args.Get(0).(uuid.UUID), mockUtils.ReturnNilOrError(args, 1)
}
