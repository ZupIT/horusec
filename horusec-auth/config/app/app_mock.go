package app

import (
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	mock2 "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) GetHorusecAPIURL() string {
	args := m.MethodCalled("GetHorusecAPIURL")
	return args.Get(0).(string)
}
func (m *Mock) GetEnableApplicationAdmin() bool {
	args := m.MethodCalled("GetEnableApplicationAdmin")
	return args.Get(0).(bool)
}
func (m *Mock) GetDisabledBroker() bool {
	args := m.MethodCalled("GetDisabledBroker")
	return args.Get(0).(bool)
}
func (m *Mock) GetApplicationAdminData() (entity *dto.CreateAccount, err error) {
	args := m.MethodCalled("GetApplicationAdminData")
	return args.Get(0).(*dto.CreateAccount), mock2.ReturnNilOrError(args, 1)
}
func (m *Mock) GetAuthType() authEnums.AuthorizationType {
	args := m.MethodCalled("GetAuthType")
	return args.Get(0).(authEnums.AuthorizationType)
}
