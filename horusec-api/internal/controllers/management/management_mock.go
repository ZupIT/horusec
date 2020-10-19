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
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	horusecEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) ListVulnManagementData(repositoryID uuid.UUID, page, size int, vulnSeverity severity.Severity,
	vulnType horusecEnums.VulnerabilityType, vulnHash string) (vulnManagement dto.VulnManagement, err error) {
	args := m.MethodCalled("ListVulnManagementData")
	return args.Get(0).(dto.VulnManagement), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) UpdateVulnType(vulnerabilityID uuid.UUID, vulnType *dto.UpdateVulnType) (*horusec.Vulnerability, error) {
	args := m.MethodCalled("UpdateVulnType")
	return args.Get(0).(*horusec.Vulnerability), mockUtils.ReturnNilOrError(args, 1)
}
