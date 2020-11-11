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

func (m *Mock) ListAll(companyID uuid.UUID) (*[]webhook.Webhook, error) {
	args := m.MethodCalled("ListAll")
	return args.Get(0).(*[]webhook.Webhook), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) ListAllByRepositoryID(repositoryID uuid.UUID) (*[]webhook.Webhook, error) {
	args := m.MethodCalled("ListAllByRepositoryID")
	return args.Get(0).(*[]webhook.Webhook), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) Create(wh *webhook.Webhook) (uuid.UUID, error) {
	args := m.MethodCalled("Create")
	return args.Get(0).(uuid.UUID), utilsMock.ReturnNilOrError(args, 1)
}
func (m *Mock) Update(wh *webhook.Webhook) error {
	args := m.MethodCalled("Update")
	return utilsMock.ReturnNilOrError(args, 0)
}
func (m *Mock) Remove(webhookID uuid.UUID) error {
	args := m.MethodCalled("Remove")
	return utilsMock.ReturnNilOrError(args, 0)
}