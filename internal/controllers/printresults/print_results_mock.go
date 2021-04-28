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

package printresults

import (
	"github.com/stretchr/testify/mock"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	utilsMock "github.com/ZupIT/horusec-devkit/pkg/utils/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) StartPrintResults() (totalVulns int, err error) {
	args := m.MethodCalled("StartPrintResults")
	return args.Get(0).(int), utilsMock.ReturnNilOrError(args, 0)
}

func (m *Mock) SetAnalysis(analysis *entitiesAnalysis.Analysis) {
	_ = m.MethodCalled("SetAnalysis")
}
