package webhook

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestWebhook_GetMethod(t *testing.T) {
	t.Run("Should return string by method valid", func(t *testing.T) {
		w := Webhook{
			Method: "post",
		}
		assert.Equal(t, http.MethodPost, w.GetMethod())
		w = Webhook{
			Method: "put",
		}
		assert.Equal(t, http.MethodPut, w.GetMethod())
		w = Webhook{
			Method: "patch",
		}
		assert.Equal(t, http.MethodPatch, w.GetMethod())
		w = Webhook{
			Method: "get",
		}
		assert.Equal(t, "", w.GetMethod())
		w = Webhook{
			Method: "other",
		}
		assert.Equal(t, "", w.GetMethod())
	})
}

func TestWebhook_GetTable(t *testing.T) {
	t.Run("should return table name", func(t *testing.T) {
		w := Webhook{}
		assert.Equal(t, "webhooks", w.GetTable())
	})
}
