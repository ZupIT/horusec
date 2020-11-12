package webhook

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHeaderType_Value(t *testing.T) {
	var h HeaderType
	h = []Headers{
		{
			Key:   "Authorization",
			Value: "Bearer Token",
		},
	}
	response, err := h.Value()
	assert.NoError(t, err)
	assert.NotEmpty(t, response)
}

func TestHeaderType_Scan(t *testing.T) {
	t.Run("Should scan content to replace in gorm with error", func(t *testing.T) {
		var h HeaderType
		assert.Error(t, h.Scan("wrong type"))
	})
	t.Run("Should scan content to replace in gorm with success", func(t *testing.T) {
		var h HeaderType
		bytes, err := json.Marshal([]Headers{
			{
				Key:   "Authorization",
				Value: "Bearer Token",
			},
		})
		assert.NoError(t, err)
		assert.NotEmpty(t, bytes)
		assert.NoError(t, h.Scan(bytes))
	})
}