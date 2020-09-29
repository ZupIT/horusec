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

package mock

import (
	"github.com/stretchr/testify/mock"
)

func ReturnInt(args mock.Arguments, index int) int {
	if len(args) >= index {
		if value, ok := args.Get(index).(int); ok {
			return value
		}
	}

	return 1
}

func ReturnBool(args mock.Arguments, index int) bool {
	if len(args) >= index {
		if value, ok := args.Get(index).(bool); ok {
			return value
		}
	}

	return false
}

func ReturnNilOrError(args mock.Arguments, index int) error {
	if len(args) >= index {
		if err, ok := args.Get(index).(error); ok {
			return err
		}
	}

	return nil
}
