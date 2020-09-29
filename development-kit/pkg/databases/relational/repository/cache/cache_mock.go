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

package cache

import (
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	utilsMock "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) Get(key string) (*cache.Cache, error) {
	args := m.MethodCalled("Get")
	return args.Get(0).(*cache.Cache), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) Exists(key string) bool {
	args := m.MethodCalled("Exists")
	return args.Get(0).(bool)
}
func (m *Mock) Set(entity *cache.Cache, expiration time.Duration) error {
	args := m.MethodCalled("Set")
	return utilsMock.ReturnNilOrError(args, 0)
}
func (m *Mock) Del(key string) error {
	args := m.MethodCalled("Del")
	return utilsMock.ReturnNilOrError(args, 0)
}
