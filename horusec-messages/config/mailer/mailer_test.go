package mailer

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestSetUp(t *testing.T) {
	t.Run("Should configure mailer and not return panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			_ = os.Setenv("HORUSEC_SMTP_ADDRESS", "smtp.mailtrap.io")
			_ = os.Setenv("HORUSEC_SMTP_USERNAME", "-")
			_ = os.Setenv("HORUSEC_SMTP_PASSWORD", "-")
			_ = os.Setenv("HORUSEC_SMTP_HOST", "smtp.mailtrap.io")
			_ = os.Setenv("HORUSEC_SMTP_PORT", "2525")
			_ = os.Setenv("HORUSEC_EMAIL_FROM", "horusec@zup.com.br")
			SetUp()
		})
	})
	t.Run("Should configure mailer and return panic", func(t *testing.T) {
		assert.Panics(t, func() {
			_ = os.Setenv("HORUSEC_SMTP_ADDRESS", "")
			_ = os.Setenv("HORUSEC_SMTP_USERNAME", "")
			_ = os.Setenv("HORUSEC_SMTP_PASSWORD", "")
			_ = os.Setenv("HORUSEC_SMTP_HOST", "")
			_ = os.Setenv("HORUSEC_SMTP_PORT", "")
			_ = os.Setenv("HORUSEC_EMAIL_FROM", "")
			SetUp()
		})
	})
}