package images

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCustomImages(t *testing.T) {
	t.Run("Should return all languages enable and in custom expected", func(t *testing.T) {
		assert.Equal(t, 16, len(NewCustomImages()))
	})
}
