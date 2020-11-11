package webhook

import (
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/google/uuid"
	"time"
)

type ResponseWebhook struct {
	WebhookID    uuid.UUID                  `json:"webhookID"`
	Description  string                     `json:"description"`
	Method       string                     `json:"method"`
	URL          string                     `json:"url"`
	Headers      HeaderType                 `json:"headers" sql:"type:"jsonb"`
	RepositoryID uuid.UUID                  `json:"repositoryID"`
	Repository   account.Repository `json:"repository" gorm:"foreignkey:RepositoryID;association_foreignkey:RepositoryID"`
	CompanyID    uuid.UUID                  `json:"companyID"`
	CreatedAt    time.Time                  `json:"createdAt"`
	UpdatedAt    time.Time                  `json:"updatedAt"`
}
