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

package testutil

import (
	"github.com/stretchr/testify/mock"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	mockutils "github.com/ZupIT/horusec-devkit/pkg/utils/mock"
)

type PrintResultsMock struct {
	mock.Mock
}

func NewPrintResultsMock() *PrintResultsMock {
	return new(PrintResultsMock)
}

func (m *PrintResultsMock) Print() (totalVulns int, err error) {
	args := m.MethodCalled("StartPrintResults")
	return args.Get(0).(int), mockutils.ReturnNilOrError(args, 0)
}

func (m *PrintResultsMock) SetAnalysis(analysis *entitiesAnalysis.Analysis) {
	_ = m.MethodCalled("SetAnalysis")
}
