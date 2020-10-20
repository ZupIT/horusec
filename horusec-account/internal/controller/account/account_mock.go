package account

import (
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	mock2 "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"time"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) CreateAccount(account *accountEntities.Account) error {
	args := m.MethodCalled("CreateAccount")
	return mock2.ReturnNilOrError(args, 0)
}
func (m *Mock) CreateAccountFromKeycloak(keyCloakToken *accountEntities.KeycloakToken) error {
	args := m.MethodCalled("CreateAccountFromKeycloak")
	return mock2.ReturnNilOrError(args, 0)
}
func (m *Mock) Login(loginData *accountEntities.LoginData) (*accountEntities.LoginResponse, error) {
	args := m.MethodCalled("Login")
	return args.Get(0).(*accountEntities.LoginResponse), mock2.ReturnNilOrError(args, 1)
}
func (m *Mock) ValidateEmail(accountID uuid.UUID) error {
	args := m.MethodCalled("ValidateEmail")
	return mock2.ReturnNilOrError(args, 0)
}
func (m *Mock) SendResetPasswordCode(email string) error {
	args := m.MethodCalled("SendResetPasswordCode")
	return mock2.ReturnNilOrError(args, 0)
}
func (m *Mock) VerifyResetPasswordCode(data *accountEntities.ResetCodeData) (string, error) {
	args := m.MethodCalled("VerifyResetPasswordCode")
	return args.Get(0).(string), mock2.ReturnNilOrError(args, 1)
}
func (m *Mock) ChangePassword(accountID uuid.UUID, password string) error {
	args := m.MethodCalled("ChangePassword")
	return mock2.ReturnNilOrError(args, 0)
}
func (m *Mock) RenewToken(refreshToken, accessToken string) (*accountEntities.LoginResponse, error) {
	args := m.MethodCalled("RenewToken")
	return args.Get(0).(*accountEntities.LoginResponse), mock2.ReturnNilOrError(args, 1)
}
func (m *Mock) Logout(accountID uuid.UUID) error {
	args := m.MethodCalled("Logout")
	return mock2.ReturnNilOrError(args, 0)
}
func (m *Mock) createTokenWithAccountPermissions(account *accountEntities.Account) (string, time.Time, error) {
	args := m.MethodCalled("createTokenWithAccountPermissions")
	return args.Get(0).(string), args.Get(1).(time.Time), mock2.ReturnNilOrError(args, 2)
}
func (m *Mock) VerifyAlreadyInUse(validateUnique *accountEntities.ValidateUnique) error {
	args := m.MethodCalled("VerifyAlreadyInUse")
	return mock2.ReturnNilOrError(args, 0)
}
