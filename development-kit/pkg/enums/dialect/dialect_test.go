package dialect

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDialect_ToString(t *testing.T) {
	assert.Equal(t, Postgres.ToString(), "postgres")
	assert.Equal(t, SQLite.ToString(), "sqlite")
}

func TestDialect_Values(t *testing.T) {
	var dialect Dialect
	assert.Len(t, dialect.Values(), 2)
}

func TestDialect_IsValid(t *testing.T) {
	t.Run("Should return valid to postgres", func(t *testing.T) {
		assert.True(t, Postgres.IsValid())
	})
	t.Run("Should return valid to sqlite", func(t *testing.T) {
		assert.True(t, SQLite.IsValid())
	})
	t.Run("Should return invalid to unknown", func(t *testing.T) {
		assert.False(t, Unknown.IsValid())
	})
}
