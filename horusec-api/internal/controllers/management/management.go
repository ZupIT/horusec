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
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/vulnerability"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/google/uuid"
)

type IController interface {
	ListVulnManagementData(repositoryID uuid.UUID, page, size int, vulnType severity.Severity,
		vulnHash string) (vulnManagement dto.VulnManagement, err error)
	UpdateVulnType(vulnerabilityID uuid.UUID, vulnType *dto.UpdateVulnType) (*horusec.Vulnerability, error)
}

type Controller struct {
	managementRepository vulnerability.IRepository
}

func NewManagementController(postgresRead relational.InterfaceRead,
	postgresWrite relational.InterfaceWrite) IController {
	return &Controller{
		managementRepository: vulnerability.NewManagementRepository(postgresRead, postgresWrite),
	}
}

func (c *Controller) ListVulnManagementData(repositoryID uuid.UUID, page, size int,
	vulnSeverity severity.Severity, vulnHash string) (vulnManagement dto.VulnManagement, err error) {
	return c.managementRepository.ListVulnManagementData(repositoryID, page, size, vulnSeverity, vulnHash)
}

func (c *Controller) UpdateVulnType(vulnerabilityID uuid.UUID,
	updateTypeData *dto.UpdateVulnType) (*horusec.Vulnerability, error) {
	return c.managementRepository.UpdateVulnType(vulnerabilityID, updateTypeData)
}
