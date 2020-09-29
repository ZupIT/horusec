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
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestMockRead_Connect(t *testing.T) {
	m := &MockRead{}
	m.On("Connect").Return(response.NewResponse(0, nil, nil))
	assert.NoError(t, m.Connect().GetError())
}
func TestMockRead_GetConnection(t *testing.T) {
	m := &MockRead{}
	m.On("GetConnection").Return(&gorm.DB{})
	assert.IsType(t, m.GetConnection(), &gorm.DB{})
}
func TestMockRead_IsAvailable(t *testing.T) {
	m := &MockRead{}
	m.On("IsAvailable").Return(true)
	assert.True(t, m.IsAvailable())
}
func TestMockRead_SetLogMode(t *testing.T) {
	m := &MockRead{}
	m.On("SetLogMode")
	assert.NotPanics(t, func() {
		m.SetLogMode(false)
	})
}
func TestMockRead_Find(t *testing.T) {
	m := &MockRead{}
	m.On("Find").Return(response.NewResponse(0, nil, nil))
	assert.NoError(t, m.Find(nil, &gorm.DB{}, "").GetError())
}
func TestMockWrite_Connect(t *testing.T) {
	m := &MockWrite{}
	m.On("Connect").Return(response.NewResponse(0, nil, nil))
	assert.NoError(t, m.Connect().GetError())
}
func TestMockWrite_GetConnection(t *testing.T) {
	m := &MockWrite{}
	m.On("GetConnection").Return(&gorm.DB{})
	assert.IsType(t, m.GetConnection(), &gorm.DB{})
}
func TestMockWrite_IsAvailable(t *testing.T) {
	m := &MockWrite{}
	m.On("IsAvailable").Return(true)
	assert.True(t, m.IsAvailable())
}
func TestMockWrite_SetLogMode(t *testing.T) {
	m := &MockWrite{}
	m.On("SetLogMode")
	assert.NotPanics(t, func() {
		m.SetLogMode(false)
	})
}
func TestMockWrite_Create(t *testing.T) {
	m := &MockWrite{}
	m.On("Create").Return(response.NewResponse(0, nil, nil))
	assert.NoError(t, m.Create(nil, "").GetError())
}
func TestMockWrite_Update(t *testing.T) {
	m := &MockWrite{}
	m.On("Update").Return(response.NewResponse(0, nil, nil))
	assert.NoError(t, m.Update(nil, map[string]interface{}{}, "").GetError())
}
func TestMockWrite_Delete(t *testing.T) {
	m := &MockWrite{}
	m.On("Delete").Return(response.NewResponse(0, nil, nil))
	assert.NoError(t, m.Delete(map[string]interface{}{}, "").GetError())
}
func TestMockWrite_StartTransaction(t *testing.T) {
	m := &MockWrite{}
	m.On("StartTransaction").Return(m)
	assert.NotPanics(t, func() {
		m.StartTransaction()
	})
}
func TestMockWrite_CommitTransaction(t *testing.T) {
	m := &MockWrite{}
	m.On("CommitTransaction").Return(response.NewResponse(0, nil, nil))
	assert.NoError(t, m.CommitTransaction().GetError())
}
func TestMockWrite_RollbackTransaction(t *testing.T) {
	m := &MockWrite{}
	m.On("RollbackTransaction").Return(response.NewResponse(0, nil, nil))
	assert.NoError(t, m.RollbackTransaction().GetError())
}
func TestMockRead_RawSQL(t *testing.T) {
	m := &MockRead{}
	m.On("RawSQL").Return(response.NewResponse(0, nil, nil))
	assert.NoError(t, m.RawSQL("", nil).GetError())
}
