package webhook

import (
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	webhookRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/webhook"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/google/uuid"
	"time"
)

type IController interface {
	ListAll(companyID uuid.UUID) (*[]webhook.ResponseWebhook, error)
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

func (c *Controller) ListAll(companyID uuid.UUID) (*[]webhook.ResponseWebhook, error) {
	return c.webhookRepository.GetAllByCompanyID(companyID)
}

func (c *Controller) Create(wh *webhook.Webhook) (uuid.UUID, error) {
	wh.CreatedAt = time.Now()
	wh.UpdatedAt = time.Now()
	wh.WebhookID = uuid.New()
	err := c.webhookRepository.Create(wh)
	if err != nil {
		if err.Error() == errorsEnum.ErrorAlreadyExistingRepositoryIDInWebhook {
			return uuid.Nil, errorsEnum.ErrorAlreadyExistsWebhookToRepository
		}
		return uuid.Nil, err
	}
	return wh.WebhookID, nil
}

func (c *Controller) Update(wh *webhook.Webhook) error {
	wh.UpdatedAt = time.Now()
	_, err := c.webhookRepository.GetByWebhookID(wh.WebhookID)
	if err != nil {
		return err
	}
	return c.webhookRepository.Update(wh)
}

func (c *Controller) Remove(webhookID uuid.UUID) error {
	_, err := c.webhookRepository.GetByWebhookID(webhookID)
	if err != nil {
		return err
	}
	return c.webhookRepository.Remove(webhookID)
}
