package images

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCustomImages(t *testing.T) {
	t.Run("Should return 12 languages enable and in custom expected", func(t *testing.T) {
		assert.Equal(t, 12, len(NewCustomImages()))
	})
}
