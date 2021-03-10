package severities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapCriticalValues(t *testing.T) {
	t.Run("should success return a critical severity map", func(t *testing.T) {
		result := MapCriticalValues()
		assert.NotEmpty(t, result)
	})
}
