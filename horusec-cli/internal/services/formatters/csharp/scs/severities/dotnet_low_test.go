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

package severities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapLowValues(t *testing.T) {
	t.Run("should success return a low severity map", func(t *testing.T) {
		result := MapLowValues()
		assert.NotEmpty(t, result)
	})
}

func TestGetLowSeverityByCode(t *testing.T) {
	t.Run("should success return a low severity", func(t *testing.T) {
		result := GetLowSeverityByCode("SCS0030")
		assert.NotEmpty(t, result)
	})

	t.Run("should return a empty low severity", func(t *testing.T) {
		result := GetLowSeverityByCode("SCS0029")
		assert.Empty(t, result)
	})
}

func TestIsLowSeverity(t *testing.T) {
	t.Run("should return true for low severity", func(t *testing.T) {
		result := IsLowSeverity("SCS0030")
		assert.True(t, result)
	})

	t.Run("should return false for low severity", func(t *testing.T) {
		result := IsLowSeverity("SCS0029")
		assert.False(t, result)
	})
}
