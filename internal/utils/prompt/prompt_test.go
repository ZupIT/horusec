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

package prompt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrompt_Ask(t *testing.T) {
	t.Run("Should run command ask without panics", func(t *testing.T) {
		assert.NotPanics(t, func() {
			go func() {
				_, _ = NewPrompt().Ask("", "")
			}()
		})
	})
}

func TestPrompt_Select(t *testing.T) {
	t.Run("Should run command select without panics", func(t *testing.T) {
		assert.NotPanics(t, func() {
			go func() {
				_, _ = NewPrompt().Select("", []string{})
			}()
		})
	})
}

func TestMock_Ask(t *testing.T) {
	mock := &Mock{}
	mock.On("Ask").Return("", nil)
	_, err := mock.Ask("", "")
	assert.NoError(t, err)
}

func TestMock_Select(t *testing.T) {
	mock := &Mock{}
	mock.On("Select").Return("", nil)
	_, err := mock.Select("", []string{})
	assert.NoError(t, err)
}
