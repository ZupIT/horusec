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
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/vulnerability"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
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
		repositoryMock := &vulnerability.Mock{}

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

func TestUpdateVulnType(t *testing.T) {
	t.Run("should success update data with no errors", func(t *testing.T) {
		repositoryMock := &vulnerability.Mock{}

		repositoryMock.On("Update").Return(&horusec.Vulnerability{}, nil)
		repositoryMock.On("GetVulnByID").Return(&horusec.Vulnerability{}, nil)

		controller := Controller{managementRepository: repositoryMock}

		_, err := controller.UpdateVulnType(uuid.New(), &dto.UpdateVulnType{})
		assert.NoError(t, err)
	})

	t.Run("should return error while getting vulnerability", func(t *testing.T) {
		repositoryMock := &vulnerability.Mock{}

		repositoryMock.On("GetVulnByID").Return(&horusec.Vulnerability{}, errors.New("test"))

		controller := Controller{managementRepository: repositoryMock}

		_, err := controller.UpdateVulnType(uuid.New(), &dto.UpdateVulnType{})
		assert.Error(t, err)
	})
}

func TestUpdateVulnStatus(t *testing.T) {
	t.Run("should success update data with no errors", func(t *testing.T) {
		repositoryMock := &vulnerability.Mock{}

		repositoryMock.On("Update").Return(&horusec.Vulnerability{}, nil)
		repositoryMock.On("GetVulnByID").Return(&horusec.Vulnerability{}, nil)

		controller := Controller{managementRepository: repositoryMock}

		_, err := controller.UpdateVulnStatus(uuid.New(), &dto.UpdateVulnStatus{})
		assert.NoError(t, err)
	})

	t.Run("should return error while getting vulnerability", func(t *testing.T) {
		repositoryMock := &vulnerability.Mock{}

		repositoryMock.On("GetVulnByID").Return(&horusec.Vulnerability{}, errors.New("test"))

		controller := Controller{managementRepository: repositoryMock}

		_, err := controller.UpdateVulnStatus(uuid.New(), &dto.UpdateVulnStatus{})
		assert.Error(t, err)
	})
}
