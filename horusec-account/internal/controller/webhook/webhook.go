package webhook

import (
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	webhookRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/webhook"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	"github.com/google/uuid"
)

type IController interface {
	ListAll(companyID uuid.UUID) (*[]webhook.Webhook, error)
	ListAllByRepositoryID(repositoryID uuid.UUID) (*[]webhook.Webhook, error)
	Create(wh *webhook.Webhook) (uuid.UUID, error)
	Update(wh *webhook.Webhook) error
	Remove(webhookID uuid.UUID) error
}

type Controller struct {
	webhookRepository webhookRepository.IWebhook
}

func NewController(databaseWrite SQL.InterfaceWrite, databaseRead SQL.InterfaceRead) IController {
	return &Controller{
		webhookRepository: webhookRepository.NewWebhookRepository(databaseRead, databaseWrite),
	}
}

func (c *Controller) ListAll(companyID uuid.UUID) (*[]webhook.Webhook, error) {
	panic("implement me")
}

func (c *Controller) ListAllByRepositoryID(repositoryID uuid.UUID) (*[]webhook.Webhook, error) {
	panic("implement me")
}

func (c *Controller) Create(wh *webhook.Webhook) (uuid.UUID, error) {
	panic("implement me")
}

func (c *Controller) Update(wh *webhook.Webhook) error {
	panic("implement me")
}

func (c *Controller) Remove(webhookID uuid.UUID) error {
	panic("implement me")
}
