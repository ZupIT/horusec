package dist

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsStandAlone(t *testing.T) {
	t.Run("should return false when the distribuition is not a stand alone distribution", func(t *testing.T) {
		s := IsStandAlone()
		assert.False(t, s)
	})
}

func TestGetVersion(t *testing.T) {
	t.Run("should return stand-alone when the distribution is a stand alone distribution", func(t *testing.T) {
		standAlone = "true"
		v := GetVersion()
		assert.Equal(t, v, "stand-alone")
	})

	t.Run("should return normal when the distribution is not a stand alone distribution", func(t *testing.T) {
		standAlone = "false"
		v := GetVersion()
		assert.Equal(t, v, "normal")
	})
}
