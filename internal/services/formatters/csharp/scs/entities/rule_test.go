package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDescription(t *testing.T) {
	t.Run("should return empty string", func(t *testing.T) {
		rule := Rule{
			ID: "test",
			FullDescription: Message{
				Text: "{test}",
			},
			HelpURI: "test",
		}

		assert.Equal(t, "test\ntest For more information, check the following url (test).",
			rule.GetDescription("test"))
	})
}
