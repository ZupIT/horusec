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

package broker

import (
	brokerPacket "github.com/ZupIT/horusec/development-kit/pkg/services/broker/packet"
	mockUtils "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) IsAvailable() bool {
	args := m.MethodCalled("IsAvailable")
	return mockUtils.ReturnBool(args, 0)
}

func (m *Mock) Publish(queue, exchange, exchangeKind string, body []byte) error {
	args := m.MethodCalled("Publish")
	return mockUtils.ReturnNilOrError(args, 0)
}

func (m *Mock) Consume(queue, exchange, exchangeKind string, handler func(packet brokerPacket.IPacket)) {
	_ = m.MethodCalled("Consume")
}

func (m *Mock) Close() error {
	args := m.MethodCalled("Close")
	return mockUtils.ReturnNilOrError(args, 0)
}
