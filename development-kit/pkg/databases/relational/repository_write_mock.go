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
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/mock"
)

type MockWrite struct {
	mock.Mock
}

func (m *MockWrite) Connect() *response.Response {
	args := m.MethodCalled("Connect")
	return args.Get(0).(*response.Response)
}
func (m *MockWrite) GetConnection() *gorm.DB {
	args := m.MethodCalled("GetConnection")
	return args.Get(0).(*gorm.DB)
}
func (m *MockWrite) IsAvailable() bool {
	args := m.MethodCalled("IsAvailable")
	return args.Get(0).(bool)
}
func (m *MockWrite) Create(entity interface{}, tableName string) *response.Response {
	args := m.MethodCalled("Create")
	return args.Get(0).(*response.Response)
}
func (m *MockWrite) CreateOrUpdate(entity interface{}, conditions map[string]interface{}, tableName string) *response.Response {
	args := m.MethodCalled("CreateOrUpdate")
	return args.Get(0).(*response.Response)
}
func (m *MockWrite) Update(entity interface{}, conditions map[string]interface{}, tableName string) *response.Response {
	args := m.MethodCalled("Update")
	return args.Get(0).(*response.Response)
}
func (m *MockWrite) Delete(conditions map[string]interface{}, tableName string) *response.Response {
	args := m.MethodCalled("Delete")
	return args.Get(0).(*response.Response)
}
func (m *MockWrite) DeleteByQuery(query *gorm.DB, tableName string) *response.Response {
	args := m.MethodCalled("DeleteByQuery")
	return args.Get(0).(*response.Response)
}
func (m *MockWrite) StartTransaction() InterfaceWrite {
	args := m.MethodCalled("StartTransaction")
	return args.Get(0).(InterfaceWrite)
}
func (m *MockWrite) RollbackTransaction() *response.Response {
	args := m.MethodCalled("RollbackTransaction")
	return args.Get(0).(*response.Response)
}
func (m *MockWrite) CommitTransaction() *response.Response {
	args := m.MethodCalled("CommitTransaction")
	return args.Get(0).(*response.Response)
}
func (m *MockWrite) SetLogMode(logMode bool) {
	_ = m.MethodCalled("SetLogMode")
}
