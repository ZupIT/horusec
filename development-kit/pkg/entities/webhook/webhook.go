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
	if err != nil {
		return nil, errorsEnum.ErrorInvalidCompanyID
	}
	repositoryID, err := uuid.Parse(repositoryIDString)
	if err != nil {
		return nil, errorsEnum.ErrorInvalidRepositoryID
	}
	w.CompanyID = companyID
	w.RepositoryID = repositoryID
	return w, nil
}

func (w *Webhook) SetWebhookID(ID uuid.UUID) *Webhook {
	w.WebhookID = ID
	return w
}