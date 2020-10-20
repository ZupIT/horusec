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

package auth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsInvalid(t *testing.T) {
	t.Run("should true when invalid type", func(t *testing.T) {
		testType := AuthorizationType("test")
		assert.True(t, testType.IsInvalid())
	})

	t.Run("should false when valid type", func(t *testing.T) {
		testType := AuthorizationType("keycloak")
		assert.False(t, testType.IsInvalid())

		testType = "ldap"
		assert.False(t, testType.IsInvalid())

		testType = "horusec"
		assert.False(t, testType.IsInvalid())
	})
}

func TestValues(t *testing.T) {
	t.Run("should 3 valid auth types", func(t *testing.T) {
		var testType AuthorizationType
		assert.Len(t, testType.Values(), 3)
	})
}
