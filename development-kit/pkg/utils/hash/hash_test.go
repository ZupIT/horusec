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

package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSHA1(t *testing.T) {
	t.Run("Should generate a hash string from another string", func(t *testing.T) {
		s := "my test string"
		h, _ := GenerateSHA256(s)

		assert.NotEmpty(t, h)
	})

	t.Run("Should generate a hash string from many string", func(t *testing.T) {
		s := "project"
		s1 := "code"
		h, _ := GenerateSHA256(s, s1)

		assert.NotEmpty(t, h)
	})

	t.Run("Should generate the same output for the same input", func(t *testing.T) {
		h, _ := GenerateSHA256("code")
		h1, _ := GenerateSHA256("code")

		assert.Equal(t, h, h1)
	})
}
