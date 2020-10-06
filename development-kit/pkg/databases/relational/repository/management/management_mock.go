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
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) GetAllVulnManagementData(repositoryID uuid.UUID, page, size int, vulnType horusecEnums.AnalysisVulnerabilitiesType,
	vulnStatus horusecEnums.AnalysisVulnerabilitiesStatus) (vulnManagement dto.VulnManagement, err error) {
	args := m.MethodCalled("GetAllVulnManagementData")
	return args.Get(0).(dto.VulnManagement), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) Update(vulnerabilityID uuid.UUID, data *dto.UpdateVulnManagementData) (*horusec.Vulnerability, error) {
	args := m.MethodCalled("Update")
	return args.Get(0).(*horusec.Vulnerability), mockUtils.ReturnNilOrError(args, 1)
}
