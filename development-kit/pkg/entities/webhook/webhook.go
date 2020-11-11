package webhook

import (
	"encoding/json"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"
)

type Webhook struct {
	WebhookID    uuid.UUID         `json:"webhookID" gorm:"primary_key" swaggerignore:"true"`
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	Headers      map[string]string `json:"headers"`
	RepositoryID uuid.UUID         `json:"repositoryID" swaggerignore:"true"`
	CompanyID    uuid.UUID         `json:"companyID" swaggerignore:"true"`
}

type WebhookResponse struct {
	WebhookID   uuid.UUID      `json:"webhookID"`
	Method       string            `json:"method"`
	Headers      map[string]string `json:"headers"`
	RepositoryID uuid.UUID         `json:"repositoryID"`
	CompanyID    uuid.UUID         `json:"companyID"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
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

func (w *Webhook) Validate() error {
	return validation.ValidateStruct(w,
		validation.Field(&w.URL, validation.Required, is.URL),
		validation.Field(&w.Method, validation.Required, validation.In(
			http.MethodPost, http.MethodPut, http.MethodPatch,
		)),
		validation.Field(&w.RepositoryID, validation.Required, is.UUID),
		validation.Field(&w.CompanyID, validation.Required, is.UUID),
	)
}

func (w *Webhook) ToBytes() []byte {
	bytes, _ := json.Marshal(w)
	return bytes
}
