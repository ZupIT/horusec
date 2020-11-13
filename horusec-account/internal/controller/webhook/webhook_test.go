package webhook

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	webhookRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/webhook"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewController(t *testing.T) {
	assert.NotEmpty(t, NewController(&relational.MockWrite{}, &relational.MockRead{}))
}

func TestController_Create(t *testing.T) {
	t.Run("Should create webhook with success", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("Create").Return(nil)
		c := &Controller{
			webhookRepository: repository,
		}
		webhookID, err := c.Create(&webhook.Webhook{
			URL:    "http://example.com",
			Method: "POST",
		})
		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, webhookID)
	})
	t.Run("Should create webhook with error of duplicated", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("Create").Return(errors.New(errorsEnum.ErrorAlreadyExistingRepositoryIDInWebhook))
		c := &Controller{
			webhookRepository: repository,
		}
		webhookID, err := c.Create(&webhook.Webhook{
			URL:    "http://example.com",
			Method: "POST",
		})
		assert.Equal(t, errorsEnum.ErrorAlreadyExistsWebhookToRepository, err)
		assert.Equal(t, uuid.Nil, webhookID)
	})
	t.Run("Should create webhook with error unexpected", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		errorUnexpected := errors.New("some error")
		repository.On("Create").Return(errorUnexpected)
		c := &Controller{
			webhookRepository: repository,
		}
		webhookID, err := c.Create(&webhook.Webhook{
			URL:    "http://example.com",
			Method: "POST",
		})
		assert.Equal(t, errorUnexpected, err)
		assert.Equal(t, uuid.Nil, webhookID)
	})
}

func TestController_ListAll(t *testing.T) {
	t.Run("Should list all webhook with success", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("GetAllByCompanyID").Return(&[]webhook.ResponseWebhook{
			{URL: "http://example.com", Method: "POST"},
		}, nil)
		c := &Controller{
			webhookRepository: repository,
		}
		allWebhooks, err := c.ListAll(uuid.New())
		assert.NoError(t, err)
		assert.NotEmpty(t, allWebhooks)
	})
	t.Run("Should list all webhook with error unexpected", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("GetAllByCompanyID").Return(&[]webhook.ResponseWebhook{}, errors.New("unexpected error"))
		c := &Controller{
			webhookRepository: repository,
		}
		allWebhooks, err := c.ListAll(uuid.New())
		assert.Error(t, err)
		assert.Empty(t, allWebhooks)
	})
}

func TestController_Remove(t *testing.T) {
	t.Run("Should remove webhook with success", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("GetByWebhookID").Return(&webhook.Webhook{}, nil)
		repository.On("Remove").Return(nil)
		c := &Controller{
			webhookRepository: repository,
		}
		err := c.Remove(uuid.New())
		assert.NoError(t, err)
	})
	t.Run("Should remove webhook with error not found", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("Remove").Return(nil)
		repository.On("GetByWebhookID").Return(&webhook.Webhook{}, errorsEnum.ErrNotFoundRecords)
		c := &Controller{
			webhookRepository: repository,
		}
		err := c.Remove(uuid.New())
		assert.Equal(t, errorsEnum.ErrNotFoundRecords, err)
	})
	t.Run("Should remove webhook with error unexpected", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("Remove").Return(errors.New("unexpected error"))
		repository.On("GetByWebhookID").Return(&webhook.Webhook{}, nil)
		c := &Controller{
			webhookRepository: repository,
		}
		err := c.Remove(uuid.New())
		assert.Error(t, err)
		assert.Equal(t, "unexpected error", err.Error())
	})
}
func TestController_Update(t *testing.T) {
	t.Run("Should update webhook with success", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("GetByWebhookID").Return(&webhook.Webhook{}, nil)
		repository.On("Update").Return(nil)
		c := &Controller{
			webhookRepository: repository,
		}
		err := c.Update(&webhook.Webhook{
			WebhookID: uuid.New(),
		})
		assert.NoError(t, err)
	})
	t.Run("Should update webhook with error already exists", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("Update").Return(errors.New(errorsEnum.ErrorAlreadyExistingRepositoryIDInWebhook))
		repository.On("GetByWebhookID").Return(&webhook.Webhook{}, nil)
		c := &Controller{
			webhookRepository: repository,
		}
		err := c.Update(&webhook.Webhook{
			WebhookID: uuid.New(),
		})
		assert.Equal(t, errorsEnum.ErrorAlreadyExistsWebhookToRepository, err)
	})
	t.Run("Should update webhook with error not found", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("Update").Return(nil)
		repository.On("GetByWebhookID").Return(&webhook.Webhook{}, errorsEnum.ErrNotFoundRecords)
		c := &Controller{
			webhookRepository: repository,
		}
		err := c.Update(&webhook.Webhook{
			WebhookID: uuid.New(),
		})
		assert.Equal(t, errorsEnum.ErrNotFoundRecords, err)
	})
	t.Run("Should update webhook with error unexpected", func(t *testing.T) {
		repository := &webhookRepository.Mock{}
		repository.On("Update").Return(errors.New("unexpected error"))
		repository.On("GetByWebhookID").Return(&webhook.Webhook{}, nil)
		c := &Controller{
			webhookRepository: repository,
		}
		err := c.Update(&webhook.Webhook{
			WebhookID: uuid.New(),
		})
		assert.Error(t, err)
		assert.Equal(t, "unexpected error", err.Error())
	})
}
