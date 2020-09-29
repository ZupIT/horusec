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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMapHighValues(t *testing.T) {
	t.Run("should success return a high severity map", func(t *testing.T) {
		result := MapHighValues()
		assert.NotEmpty(t, result)
	})
}

func TestGetHighSeverityByCode(t *testing.T) {
	t.Run("should success return a high severity", func(t *testing.T) {
		result := GetHighSeverityByCode("SCS0029")
		assert.NotEmpty(t, result)
	})

	t.Run("should return a empty high severity", func(t *testing.T) {
		result := GetHighSeverityByCode("SCS0021")
		assert.Empty(t, result)
	})
}

func TestIsHighSeverity(t *testing.T) {
	t.Run("should return true for high severity", func(t *testing.T) {
		result := IsHighSeverity("SCS0029")
		assert.True(t, result)
	})

	t.Run("should return false for high severity", func(t *testing.T) {
		result := IsHighSeverity("SCS0021")
		assert.False(t, result)
	})
}
