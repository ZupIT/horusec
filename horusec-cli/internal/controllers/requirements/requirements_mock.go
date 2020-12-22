package requirements

import (
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) ValidateDocker() {
	_ = m.MethodCalled("ValidateDocker")
}

func (m *Mock) ValidateGit() {
	_ = m.MethodCalled("ValidateGit")
}
