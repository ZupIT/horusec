package auth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsInvalidRoles(t *testing.T) {
	t.Run("should true when invalid role", func(t *testing.T) {
		testType := HorusRoles("test")
		assert.True(t, testType.IsInvalid())
	})

	t.Run("should false when valid role", func(t *testing.T) {
		testType := HorusRoles("companyMember")
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
	t.Run("should 5 valid horus roles", func(t *testing.T) {
		testRole := RepositoryAdmin
		assert.Len(t, testRole.Values(), 5)
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
