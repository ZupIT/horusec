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
