package webhook

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	"github.com/google/uuid"
)

type IWebhook interface {
	GetByRepositoryID(repositoryID uuid.UUID) (*webhook.Webhook, error)
}

type Webhook struct {
	databaseRead  relational.InterfaceRead
	databaseWrite relational.InterfaceWrite
}

func NewWebhookRepository(databaseRead relational.InterfaceRead, databaseWrite relational.InterfaceWrite) IWebhook {
	return &Webhook{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
	}
}

func (w *Webhook) GetByRepositoryID(repositoryID uuid.UUID) (*webhook.Webhook, error) {
	entity := &webhook.Webhook{}
	filter := w.databaseRead.SetFilter(map[string]interface{}{"repository_id": repositoryID})
	response := w.databaseRead.Find(entity, filter, entity.GetTable())
	return entity, response.GetError()
}
