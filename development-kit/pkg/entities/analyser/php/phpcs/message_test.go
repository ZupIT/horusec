package phpcs

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetLine(t *testing.T) {
	message := &Message{
		Line: 1,
	}

	t.Run("should success get line", func(t *testing.T) {
		line := message.GetLine()

		assert.NotEmpty(t, line)
		assert.Equal(t, "1", line)
	})
}

func TestGetColumn(t *testing.T) {
	message := &Message{
		Column: 1,
	}

	t.Run("should success get column", func(t *testing.T) {
		column := message.GetColumn()

		assert.NotEmpty(t, column)
		assert.Equal(t, "1", column)
	})
}

func TestIsValidMessage(t *testing.T) {
	t.Run("should return false if invalid message", func(t *testing.T) {
		message := &Message{
			Message: "This implies that some PHP code is not scanned by PHPCS",
			Type:    "ERROR",
		}

		assert.False(t, message.IsValidMessage())
	})

	t.Run("should return true if valid message", func(t *testing.T) {
		message := &Message{
			Message: "",
			Type:    "ERROR",
		}

		assert.True(t, message.IsValidMessage())
	})
}
