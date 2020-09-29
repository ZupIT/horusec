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

package response

import (
	"net/http"

	utilsMock "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) ErrorByStatusCode() error {
	args := m.MethodCalled("ErrorByStatusCode")
	return utilsMock.ReturnNilOrError(args, 0)
}
func (m *Mock) GetBody() ([]byte, error) {
	args := m.MethodCalled("GetBody")
	return args.Get(0).([]byte), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) GetResponse() *http.Response {
	args := m.MethodCalled("GetResponse")
	return args.Get(0).(*http.Response)
}
func (m *Mock) GetStatusCode() int {
	args := m.MethodCalled("GetStatusCode")
	return args.Get(0).(int)
}
func (m *Mock) GetStatusCodeString() string {
	args := m.MethodCalled("GetStatusCodeString")
	return args.Get(0).(string)
}
func (m *Mock) GetContentType() string {
	args := m.MethodCalled("GetContentType")
	return args.Get(0).(string)
}
