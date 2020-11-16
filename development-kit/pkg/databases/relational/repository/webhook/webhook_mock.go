package webhook

import (
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	utilsMock "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) GetByRepositoryID(_ uuid.UUID) (*webhook.Webhook, error) {
	args := m.MethodCalled("GetByRepositoryID")
	return args.Get(0).(*webhook.Webhook), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) GetByWebhookID(webhookID uuid.UUID) (*webhook.Webhook, error) {
	args := m.MethodCalled("GetByWebhookID")
	return args.Get(0).(*webhook.Webhook), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) GetAllByCompanyID(companyID uuid.UUID) (*[]webhook.ResponseWebhook, error) {
	args := m.MethodCalled("GetAllByCompanyID")
	return args.Get(0).(*[]webhook.ResponseWebhook), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) Create(wh *webhook.Webhook) error {
	args := m.MethodCalled("Create")
	return utilsMock.ReturnNilOrError(args, 0)
}
func (m *Mock) Update(wh *webhook.Webhook) error {
	args := m.MethodCalled("Update")
	return utilsMock.ReturnNilOrError(args, 0)
}
func (m *Mock) Remove(webhookID uuid.UUID) error {
	args := m.MethodCalled("Remove")
	return utilsMock.ReturnNilOrError(args, 0)
}
