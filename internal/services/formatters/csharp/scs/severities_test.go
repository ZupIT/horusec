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

package scs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapCriticalValues(t *testing.T) {
	t.Run("should success return a critical severity map", func(t *testing.T) {
		result := criticalSeverities()
		assert.NotEmpty(t, result)
	})
}

func TestMapHighValues(t *testing.T) {
	t.Run("should success return a high severity map", func(t *testing.T) {
		result := highSeverities()
		assert.NotEmpty(t, result)
	})
}

func TestMapLowValues(t *testing.T) {
	t.Run("should success return a low severity map", func(t *testing.T) {
		result := lowSevetiries()
		assert.NotEmpty(t, result)
	})
}

func TestMapMediumValues(t *testing.T) {
	t.Run("should success return a medium severity map", func(t *testing.T) {
		result := mediumSeverities()
		assert.NotEmpty(t, result)
	})
}
