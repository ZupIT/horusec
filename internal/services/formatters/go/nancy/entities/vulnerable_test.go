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

package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetVulnerability(t *testing.T) {
	t.Run("should return first vulnerability in the array", func(t *testing.T) {
		vulnerable := Vulnerable{
			Vulnerabilities: []*Vulnerability{{}},
		}

		assert.NotNil(t, vulnerable.GetVulnerability())
	})

	t.Run("should return nil when no vulnerabilities were found", func(t *testing.T) {
		vulnerable := Vulnerable{}

		assert.Nil(t, vulnerable.GetVulnerability())
	})
}

func TestGetDependency(t *testing.T) {
	t.Run("should success get dependency path", func(t *testing.T) {
		vulnerable := Vulnerable{
			Coordinates: "pkg:golang/test@123",
		}

		assert.Equal(t, "test", vulnerable.GetDependency())
	})

	t.Run("should return dependency when no version was found", func(t *testing.T) {
		vulnerable := Vulnerable{
			Coordinates: "pkg:golang/test",
		}

		assert.Equal(t, "test", vulnerable.GetDependency())
	})
}
