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
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"time"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) CreateAccount(account *accountEntities.Account) error {
	args := m.MethodCalled("CreateAccount")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) Login(loginData *accountEntities.LoginData) (*accountEntities.LoginResponse, error) {
	args := m.MethodCalled("Login")
	return args.Get(0).(*accountEntities.LoginResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) ValidateEmail(accountID uuid.UUID) error {
	args := m.MethodCalled("ValidateEmail")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) SendResetPasswordCode(email string) error {
	args := m.MethodCalled("SendResetPasswordCode")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) VerifyResetPasswordCode(data *accountEntities.ResetCodeData) (string, error) {
	args := m.MethodCalled("VerifyResetPasswordCode")
	return args.Get(0).(string), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) ChangePassword(accountID uuid.UUID, password string) error {
	args := m.MethodCalled("ChangePassword")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) RenewToken(refreshToken, accessToken string) (*accountEntities.LoginResponse, error) {
	args := m.MethodCalled("RenewToken")
	return args.Get(0).(*accountEntities.LoginResponse), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) Logout(accountID uuid.UUID) error {
	args := m.MethodCalled("Logout")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) createTokenWithAccountPermissions(account *accountEntities.Account) (string, time.Time, error) {
	args := m.MethodCalled("createTokenWithAccountPermissions")
	return args.Get(0).(string), args.Get(1).(time.Time), mockUtils.ReturnNilOrError(args, 2)
}

func (m *Mock) VerifyAlreadyInUse(validateUnique *accountEntities.ValidateUnique) error {
	args := m.MethodCalled("VerifyAlreadyInUse")
	return mockUtils.ReturnNilOrError(args, 0)
}
func (m *Mock) DeleteAccount(accountID uuid.UUID) error {
	args := m.MethodCalled("DeleteAccount")
	return mockUtils.ReturnNilOrError(args, 0)
}
func (m *Mock) GetAccountIDByEmail(email string) (uuid.UUID, error) {
	args := m.MethodCalled("GetAccountIDByEmail")
	return args.Get(0).(uuid.UUID), mockUtils.ReturnNilOrError(args, 1)
}
