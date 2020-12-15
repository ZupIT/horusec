package health

import (
	"github.com/stretchr/testify/mock"
)

type MockHealthCheckClient struct {
	mock.Mock
}

func (m *MockHealthCheckClient) IsAvailable() (bool, string) {
	args := m.MethodCalled("IsAvailable")
	return args.Get(0).(bool), args.Get(1).(string)
}
