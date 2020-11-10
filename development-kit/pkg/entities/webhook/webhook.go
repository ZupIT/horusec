package webhook

import (
	"github.com/google/uuid"
	"net/http"
	"strings"
)

type Webhook struct {
	WebhookID    uuid.UUID         `json:"webhookID"`
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	Headers      map[string]string `json:"headers"`
	RepositoryID uuid.UUID         `json:"repositoryID"`
}

func (w *Webhook) GetTable() string {
	return "webhooks"
}

func (w *Webhook) GetMethod() string {
	switch strings.ToUpper(w.Method) {
	case "POST":
		return http.MethodPost
	case "PUT":
		return http.MethodPut
	case "PATCH":
		return http.MethodPatch
	default:
		return ""
	}
}
