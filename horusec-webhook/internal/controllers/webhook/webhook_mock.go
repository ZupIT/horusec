package webhook

import (
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	utilsMock "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) DispatchRequest(_ *horusec.Analysis) error {
	args := m.MethodCalled("DispatchRequest")
	return utilsMock.ReturnNilOrError(args, 0)
}
