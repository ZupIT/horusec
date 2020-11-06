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

func TestIsInvalidRoles(t *testing.T) {
	t.Run("should true when invalid role", func(t *testing.T) {
		testType := HorusecRoles("test")
		assert.True(t, testType.IsInvalid())
	})

	t.Run("should false when valid role", func(t *testing.T) {
		testType := HorusecRoles("companyMember")
		assert.False(t, testType.IsInvalid())

		testType = "companyAdmin"
		assert.False(t, testType.IsInvalid())

		testType = "repositoryMember"
		assert.False(t, testType.IsInvalid())

		testType = "repositorySupervisor"
		assert.False(t, testType.IsInvalid())

		testType = "repositoryAdmin"
		assert.False(t, testType.IsInvalid())
	})
}

func TestValuesRoles(t *testing.T) {
	t.Run("should 6 valid horus roles", func(t *testing.T) {
		testRole := RepositoryAdmin
		assert.Len(t, testRole.Values(), 6)
	})
}

func TestIsEqual(t *testing.T) {
	t.Run("should return true when equal", func(t *testing.T) {
		testRole := RepositoryAdmin
		assert.True(t, testRole.IsEqual(testRole.ToString()))
	})

	t.Run("should return false when equal", func(t *testing.T) {
		testRole := RepositoryAdmin
		assert.False(t, testRole.IsEqual("test"))
	})
}

func TestToStringRoles(t *testing.T) {
	t.Run("should parse to string", func(t *testing.T) {
		testType := RepositorySupervisor

		assert.IsType(t, "", testType.ToString())
	})
}
