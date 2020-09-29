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

package pagination

import (
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestGetSkip(t *testing.T) {
	t.Run("should success get skip size", func(t *testing.T) {
		assert.Equal(t, GetSkip(1, 2), int64(0))
		assert.Equal(t, GetSkip(2, 10), int64(10))
	})
}

func TestGetTotalPages(t *testing.T) {
	t.Run("should success get total pages", func(t *testing.T) {
		assert.Equal(t, GetTotalPages(1, 1), 1)
		assert.Equal(t, GetTotalPages(1, 2), 2)
		assert.Equal(t, GetTotalPages(5, 18), 4)
		assert.Equal(t, GetTotalPages(3, 20), 7)
		assert.Equal(t, GetTotalPages(0, 0), 0)
	})
}
