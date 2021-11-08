// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package dist

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsStandAlone(t *testing.T) {
	t.Run("should return false when the distribution is not a stand alone distribution", func(t *testing.T) {
		assert.False(t, IsStandAlone())
	})
}

func TestGetVersion(t *testing.T) {
	t.Run("should return stand-alone when the distribution is a stand alone distribution", func(t *testing.T) {
		standAlone = "true"
		assert.Equal(t, Mode(), StandAlone)
	})

	t.Run("should return normal when the distribution is not a stand alone distribution", func(t *testing.T) {
		standAlone = "false"
		assert.Equal(t, Mode(), Normal)
	})
}
