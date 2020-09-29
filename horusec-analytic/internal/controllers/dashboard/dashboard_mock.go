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

package dashboard

import (
	"time"

	dashboardEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/dashboard"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/graphql-go/graphql"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) GetVulnerabilitiesByAuthor(query string, page, size int) (*graphql.Result, error) {
	args := m.MethodCalled("GetVulnerabilitiesByAuthor")
	return args.Get(0).(*graphql.Result), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetTotalDevelopers(companyID, repositoryID uuid.UUID, initialDate, finalDate time.Time) (int, error) {
	args := m.MethodCalled("GetTotalDevelopers")
	return args.Get(0).(int), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetTotalRepositories(companyID, repositoryID uuid.UUID, initialDate, finalDate time.Time) (int, error) {
	args := m.MethodCalled("GetTotalRepositories")
	return args.Get(0).(int), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetVulnBySeverity(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) ([]dashboardEntities.VulnBySeverity, error) {
	args := m.MethodCalled("GetVulnBySeverity")
	return args.Get(0).([]dashboardEntities.VulnBySeverity), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetVulnByDeveloper(companyID, repositoryID uuid.UUID,
	initialDate, finalDate time.Time) ([]dashboardEntities.VulnByDeveloper, error) {
	args := m.MethodCalled("GetVulnByDeveloper")
	return args.Get(0).([]dashboardEntities.VulnByDeveloper), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetVulnByLanguage(companyID, repositoryID uuid.UUID,
	initialDate, finalDate time.Time) ([]dashboardEntities.VulnByLanguage, error) {
	args := m.MethodCalled("GetVulnByLanguage")
	return args.Get(0).([]dashboardEntities.VulnByLanguage), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetVulnByTime(companyID, repositoryID uuid.UUID,
	initialDate, finalDate time.Time) ([]dashboardEntities.VulnByTime, error) {
	args := m.MethodCalled("GetVulnByTime")
	return args.Get(0).([]dashboardEntities.VulnByTime), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetVulnByRepository(companyID, repositoryID uuid.UUID,
	initialDate, finalDate time.Time) ([]dashboardEntities.VulnByRepository, error) {
	args := m.MethodCalled("GetVulnByRepository")
	return args.Get(0).([]dashboardEntities.VulnByRepository), mockUtils.ReturnNilOrError(args, 1)
}
