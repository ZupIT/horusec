package webhook

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/google/uuid"
)

type IWebhook interface {
	GetByRepositoryID(repositoryID uuid.UUID) (*webhook.Webhook, error)
	GetByWebhookID(webhookID uuid.UUID) (*webhook.Webhook, error)
	GetAllByCompanyID(companyID uuid.UUID) (*[]webhook.ResponseWebhook, error)
	Create(wh *webhook.Webhook) error
	Update(wh *webhook.Webhook) error
	Remove(webhookID uuid.UUID) error
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
	filter := w.databaseRead.SetFilter(map[string]interface{}{"repository_id": repositoryID}).Limit(1)
	response := w.databaseRead.Find(entity, filter, entity.GetTable())
	return entity, response.GetError()
}

func (w *Webhook) GetByWebhookID(webhookID uuid.UUID) (*webhook.Webhook, error) {
	entity := &webhook.Webhook{}
	filter := w.databaseRead.SetFilter(map[string]interface{}{"webhook_id": webhookID}).Limit(1)
	response := w.databaseRead.Find(entity, filter, entity.GetTable())
	return entity, response.GetError()
}

func (w *Webhook) GetAllByCompanyID(companyID uuid.UUID) (listWebhook *[]webhook.ResponseWebhook, err error) {
	entity := &webhook.Webhook{}
	filter := w.databaseRead.SetFilter(map[string]interface{}{"company_id": companyID}).Preload("Repository")
	response := w.databaseRead.Find(listWebhook, filter, entity.GetTable())
	return listWebhook, response.GetError()
}

func (w *Webhook) Create(wh *webhook.Webhook) error {
	r := w.databaseWrite.Create(wh, wh.GetTable())
	if r.GetError() != nil {
		return r.GetError()
	}
	if r.GetRowsAffected() == 0 {
		return EnumErrors.ErrNotFoundRecords
	}
	return nil
}

func (w *Webhook) Update(wh *webhook.Webhook) error {
	condition := map[string]interface{}{
		"webhook_id": wh.WebhookID,
	}
	r := w.databaseWrite.Update(wh, condition, wh.GetTable())
	return r.GetError()
}

func (w *Webhook) Remove(webhookID uuid.UUID) error {
	entity := &webhook.Webhook{}
	condition := map[string]interface{}{
		"webhook_id": webhookID,
	}
	r := w.databaseWrite.Delete(condition, entity.GetTable())
	return r.GetError()
}
