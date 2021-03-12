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

package analysis

import (
	"time"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/dashboard"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) Create(_ *horusec.Analysis, _ SQL.InterfaceWrite) error {
	args := m.MethodCalled("Create")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) GetByID(_ uuid.UUID) (*horusec.Analysis, error) {
	args := m.MethodCalled("GetByID")
	return args.Get(0).(*horusec.Analysis), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetDetailsPaginated(_, _ uuid.UUID, _, _ int, _, _ time.Time) ([]dashboard.VulnDetails, error) {
	args := m.MethodCalled("GetDetailsPaginated")
	return args.Get(0).([]dashboard.VulnDetails), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetDetailsCount(_, _ uuid.UUID, _, _ time.Time) (int, error) {
	args := m.MethodCalled("GetDetailsCount")
	return args.Get(0).(int), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetDeveloperCount(_, _ uuid.UUID, _, _ time.Time) (count int, err error) {
	args := m.MethodCalled("GetDeveloperCount")
	return args.Get(0).(int), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetRepositoryCount(_, _ uuid.UUID, _, _ time.Time) (count int, err error) {
	args := m.MethodCalled("GetRepositoryCount")
	return args.Get(0).(int), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetVulnBySeverity(_, _ uuid.UUID, _, _ time.Time) ([]dashboard.VulnBySeverity, error) {
	args := m.MethodCalled("GetVulnBySeverity")
	return args.Get(0).([]dashboard.VulnBySeverity), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetVulnByDeveloper(_, _ uuid.UUID, _, _ time.Time) ([]dashboard.VulnByDeveloper, error) {
	args := m.MethodCalled("GetVulnByDeveloper")
	return args.Get(0).([]dashboard.VulnByDeveloper), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetVulnByLanguage(_, _ uuid.UUID, _, _ time.Time) ([]dashboard.VulnByLanguage, error) {
	args := m.MethodCalled("GetVulnByLanguage")
	return args.Get(0).([]dashboard.VulnByLanguage), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetVulnByRepository(_, _ uuid.UUID, _, _ time.Time) ([]dashboard.VulnByRepository, error) {
	args := m.MethodCalled("GetVulnByRepository")
	return args.Get(0).([]dashboard.VulnByRepository), mockUtils.ReturnNilOrError(args, 1)
}

func (m *Mock) GetVulnByTime(_, _ uuid.UUID, _, _ time.Time) ([]dashboard.VulnByTime, error) {
	args := m.MethodCalled("GetVulnByTime")
	return args.Get(0).([]dashboard.VulnByTime), mockUtils.ReturnNilOrError(args, 1)
}
