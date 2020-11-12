package webhook

import (
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"
)

func TestWebhook_NewWebhookFromReadCloser(t *testing.T) {
	t.Run("should parse read closer to webhook with success", func(t *testing.T) {
		w := &webhook.Webhook{
			URL:          "http://example.com",
			Method:       "POST",
		}
		readCloser := ioutil.NopCloser(strings.NewReader(string(w.ToBytes())))

		useCases := NewWebhookUseCases()
		w, err := useCases.NewWebhookFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, w)
	})
	t.Run("should parse read closer to webhook with error", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader("wrong data type"))

		useCases := NewWebhookUseCases()
		w, err := useCases.NewWebhookFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Empty(t, w)
	})
}