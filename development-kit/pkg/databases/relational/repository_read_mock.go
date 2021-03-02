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

package relational

import (
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

type MockRead struct {
	mock.Mock
}

func (m *MockRead) Connect(_, _ string, _ bool) *response.Response {
	args := m.MethodCalled("Connect")
	return args.Get(0).(*response.Response)
}
func (m *MockRead) GetConnection() *gorm.DB {
	args := m.MethodCalled("GetConnection")
	return args.Get(0).(*gorm.DB)
}
func (m *MockRead) IsAvailable() bool {
	args := m.MethodCalled("IsAvailable")
	return args.Get(0).(bool)
}
func (m *MockRead) Find(_ interface{}, _ *gorm.DB, _ string) *response.Response {
	args := m.MethodCalled("Find")
	return args.Get(0).(*response.Response)
}
func (m *MockRead) SetLogMode(_ bool) {
	_ = m.MethodCalled("SetLogMode")
}
func (m *MockRead) SetFilter(_ map[string]interface{}) *gorm.DB {
	args := m.MethodCalled("SetFilter")
	return args.Get(0).(*gorm.DB)
}
func (m *MockRead) First(_ interface{}, _ string, _ ...interface{}) *response.Response {
	args := m.MethodCalled("First")
	return args.Get(0).(*response.Response)
}
func (m *MockRead) RawSQL(_ string, _ interface{}) *response.Response {
	args := m.MethodCalled("RawSQL")
	return args.Get(0).(*response.Response)
}
