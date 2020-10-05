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

package management

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/management"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewManagementController(t *testing.T) {
	t.Run("should create a new controller", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		controller := NewManagementController(mockRead, mockWrite)

		assert.NotNil(t, controller)
	})
}

func TestGetAllVulnManagementData(t *testing.T) {
	t.Run("should success get vuln management data", func(t *testing.T) {
		repositoryMock := &management.Mock{}

		repositoryMock.On("GetAllVulnManagementData").Return(dto.VulnManagement{
			TotalItems: 1,
			Data: []dto.Data{
				{
					File: "test",
				},
			},
		}, nil)

		controller := Controller{managementRepository: repositoryMock}

		result, err := controller.GetAllVulnManagementData(uuid.New(), 1, 10, "", "")
		assert.NoError(t, err)
		assert.Equal(t, 1, result.TotalItems)
		assert.Len(t, result.Data, 1)
	})
}
