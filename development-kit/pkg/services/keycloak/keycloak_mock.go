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

package keycloak

import (
	"github.com/Nerzal/gocloak/v7"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) LoginOtp(username, password, otp string) (*gocloak.JWT, error) {
	args := m.MethodCalled("LoginOtp")
	return args.Get(0).(*gocloak.JWT), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) IsActiveToken(token string) (bool, error) {
	args := m.MethodCalled("IsActiveToken")
	return args.Get(0).(bool), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetAccountIDByJWTToken(token string) (uuid.UUID, error) {
	args := m.MethodCalled("GetAccountIDByJWTToken")
	return args.Get(0).(uuid.UUID), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetUserInfo(accessToken string) (*gocloak.UserInfo, error) {
	args := m.MethodCalled("GetUserInfo")
	return args.Get(0).(*gocloak.UserInfo), mockUtils.ReturnNilOrError(args, 1)
}
func (m *Mock) getClient() gocloak.GoCloak {
	args := m.MethodCalled("getClient")
	return args.Get(0).(gocloak.GoCloak)
}
func (m *Mock) getClientID() string {
	args := m.MethodCalled("getClientID")
	return args.Get(0).(string)
}
func (m *Mock) getClientSecret() string {
	args := m.MethodCalled("getClientSecret")
	return args.Get(0).(string)
}
func (m *Mock) getRealm() string {
	args := m.MethodCalled("getRealm")
	return args.Get(0).(string)
}
func (m *Mock) getOtp() bool {
	args := m.MethodCalled("getOtp")
	return args.Get(0).(bool)
}
