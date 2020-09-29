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

package errors

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJoinErrors(t *testing.T) {
	t.Run("Should return one error", func(t *testing.T) {
		assert.Error(t, JoinErrors(errors.New("generic")))
	})
	t.Run("Should return multiple error", func(t *testing.T) {
		err1 := errors.New("generic1")
		err2 := errors.New("generic2")
		err3 := errors.New("generic3")
		assert.Error(t, JoinErrors(err1, err2, err3))
	})
	t.Run("Should return zero error", func(t *testing.T) {
		assert.NoError(t, JoinErrors(nil))
	})
}
