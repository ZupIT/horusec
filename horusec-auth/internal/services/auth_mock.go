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

package services

import (
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/stretchr/testify/mock"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Authenticate(credentials authEntities.Credentials) (bool, map[string]interface{}, error) {
	args := m.MethodCalled("Authenticate")
	return args.Bool(0), args.Get(1).(map[string]interface{}), args.Error(2)
}

func (m *MockAuthService) IsAuthorized(authorizationData *authEntities.AuthorizationData) (bool, error) {
	args := m.MethodCalled("IsAuthorized")
	return args.Bool(0), args.Error(1)
}
