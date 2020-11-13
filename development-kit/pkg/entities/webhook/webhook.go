package webhook

import (
	"encoding/json"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"
)

type Webhook struct {
	WebhookID    uuid.UUID  `json:"webhookID" gorm:"primary_key" swaggerignore:"true"`
	Description  string     `json:"description"`
	URL          string     `json:"url"`
	Method       string     `json:"method"`
	Headers      HeaderType `json:"headers"`
	RepositoryID uuid.UUID  `json:"repositoryID" swaggerignore:"true"`
	CompanyID    uuid.UUID  `json:"companyID" swaggerignore:"true"`
	CreatedAt    time.Time  `json:"createdAt" swaggerignore:"true"`
	UpdatedAt    time.Time  `json:"updatedAt" swaggerignore:"true"`
}

func (w *Webhook) GetTable() string {
	return "webhooks"
}

func (w *Webhook) GetMethod() string {
	switch strings.ToUpper(w.Method) {
	case "POST":
		return http.MethodPost
	default:
		return ""
	}
}

func (w *Webhook) Validate() error {
	return validation.ValidateStruct(w,
		validation.Field(&w.URL, validation.Required, is.URL),
		validation.Field(&w.Method, validation.Required, validation.In(http.MethodPost)),
		validation.Field(&w.RepositoryID, validation.Required, is.UUID),
		validation.Field(&w.CompanyID, validation.Required, is.UUID),
	)
}

func (w *Webhook) ToBytes() []byte {
	bytes, _ := json.Marshal(w)
	return bytes
}

func (w *Webhook) SetCompanyIDAndRepositoryID(companyIDString, repositoryIDString string) (*Webhook, error) {
	companyID, err := uuid.Parse(companyIDString)
	if err != nil || companyID == uuid.Nil {
		return nil, errorsEnum.ErrorInvalidCompanyID
	}
	repositoryID, err := uuid.Parse(repositoryIDString)
	if err != nil || repositoryID == uuid.Nil {
		return nil, errorsEnum.ErrorInvalidRepositoryID
	}
	w.CompanyID = companyID
	w.RepositoryID = repositoryID
	return w, nil
}

func (w *Webhook) SetWebhookID(id uuid.UUID) *Webhook {
	w.WebhookID = id
	return w
}

func (w *Webhook) GetHeaders() map[string]string {
	headers := map[string]string{}
	for _, item := range w.Headers {
		headers[item.Key] = item.Value
	}
	return headers
}
