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
	mockutils "github.com/ZupIT/horusec-devkit/pkg/utils/mock"
	"github.com/stretchr/testify/mock"
)

type PromptMock struct {
	mock.Mock
}

func NewPromptMock() *PromptMock {
	return new(PromptMock)
}

func (m *PromptMock) Ask(label, defaultValue string) (string, error) {
	args := m.MethodCalled("Ask")
	return args.Get(0).(string), mockutils.ReturnNilOrError(args, 1)
}

func (m *PromptMock) Select(label string, items []string) (string, error) {
	args := m.MethodCalled("Select")
	return args.Get(0).(string), mockutils.ReturnNilOrError(args, 1)
}
