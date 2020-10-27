// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package account

import (
	"fmt"
	"time"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccount "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	entityCache "github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/messages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	emailEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/messages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/queues"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	"github.com/google/uuid"
)

type IAccount interface {
	CreateAccount(account *accountEntities.Account) error
	Login(loginData *accountEntities.LoginData) (*accountEntities.LoginResponse, error)
	ValidateEmail(accountID uuid.UUID) error
	SendResetPasswordCode(email string) error
	VerifyResetPasswordCode(data *accountEntities.ResetCodeData) (string, error)
	ChangePassword(accountID uuid.UUID, password string) error
	RenewToken(refreshToken, accessToken string) (*accountEntities.LoginResponse, error)
	Logout(accountID uuid.UUID) error
	createTokenWithAccountPermissions(account *accountEntities.Account) (string, time.Time, error)
	VerifyAlreadyInUse(validateUnique *accountEntities.ValidateUnique) error
	DeleteAccount(accountID uuid.UUID) error
}

type Account struct {
	useCases              accountUseCases.IAccount
	broker                brokerLib.IBroker
	databaseRead          SQL.InterfaceRead
	databaseWrite         SQL.InterfaceWrite
	accountRepository     repositoryAccount.IAccount
	accountRepositoryRepo repoAccountRepository.IAccountRepository
	cacheRepository       cache.Interface
	appConfig             app.IAppConfig
}

func NewAccountController(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead,
	databaseWrite SQL.InterfaceWrite, cacheRepository cache.Interface, useCases accountUseCases.IAccount,
	appConfig app.IAppConfig) IAccount {
	return &Account{
		useCases:              useCases,
		broker:                broker,
		databaseWrite:         databaseWrite,
		databaseRead:          databaseRead,
		accountRepository:     repositoryAccount.NewAccountRepository(databaseRead, databaseWrite),
		accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(databaseRead, databaseWrite),
		cacheRepository:       cacheRepository,
		appConfig:             appConfig,
	}
}

func (a *Account) CreateAccount(account *accountEntities.Account) error {
	if a.appConfig.IsEmailServiceDisabled() {
		account = account.SetIsConfirmed()
	}

	if err := a.accountRepository.Create(account.SetAccountData()); err != nil {
		return a.useCases.CheckCreateAccountErrorType(err)
	}

	return a.sendValidateAccountEmail(account)
}

func (a *Account) Login(loginData *accountEntities.LoginData) (*accountEntities.LoginResponse, error) {
	account, err := a.accountRepository.GetByEmail(loginData.Email)
	if err != nil {
		return nil, err
	}

	if err := a.useCases.ValidateLogin(account, loginData); err != nil {
		return nil, err
	}

	return a.setLoginResponse(account)
}

func (a *Account) ValidateEmail(accountID uuid.UUID) error {
	account, err := a.accountRepository.GetByAccountID(accountID)
	if err != nil {
		return err
	}

	return a.accountRepository.Update(account.SetIsConfirmed())
}

func (a *Account) sendValidateAccountEmail(account *accountEntities.Account) error {
	if a.appConfig.IsEmailServiceDisabled() {
		return nil
	}

	emailMessage := messages.EmailMessage{
		To:           account.Email,
		TemplateName: emailEnum.EmailConfirmation,
		Subject:      "[Horusec] Email confirmation",
		Data: map[string]interface{}{"Username": account.Username,
			"URL": a.getConfirmationEmailURL(account.AccountID)},
	}

	return a.broker.Publish(queues.HorusecEmail.ToString(), "", "", emailMessage.ToBytes())
}

func (a *Account) getConfirmationEmailURL(accountID uuid.UUID) string {
	apiURL := env.GetEnvOrDefault("HORUSEC_API_URL", "http://localhost:8003")
	return fmt.Sprintf("%s/api/account/validate/%s", apiURL, accountID)
}

func (a *Account) SendResetPasswordCode(email string) error {
	account, err := a.accountRepository.GetByEmail(email)
	if err != nil {
		return err
	}

	code := a.useCases.GenerateResetPasswordCode()
	err = a.cacheRepository.Set(&entityCache.Cache{Key: email, Value: []byte(code)}, time.Minute*30)
	if err != nil {
		return err
	}

	return a.sendResetPasswordEmail(account.Email, account.Username, code)
}

func (a *Account) sendResetPasswordEmail(email, username, code string) error {
	if a.appConfig.IsEmailServiceDisabled() {
		return nil
	}

	emailMessage := messages.EmailMessage{
		To:           email,
		TemplateName: emailEnum.ResetPassword,
		Subject:      "[Horusec] Reset Password",
		Data:         map[string]interface{}{"Username": username, "Code": code, "URL": a.getURLToResetPassword(email, code)},
	}

	return a.broker.Publish(queues.HorusecEmail.ToString(), "", "", emailMessage.ToBytes())
}

func (a *Account) VerifyResetPasswordCode(data *accountEntities.ResetCodeData) (string, error) {
	if err := a.checkResetPasswordCode(data); err != nil {
		return "", err
	}

	account, err := a.accountRepository.GetByEmail(data.Email)
	if err != nil {
		return "", err
	}

	_ = a.cacheRepository.Del(data.Email)

	token, _, err := a.createTokenWithAccountPermissions(account)
	return token, err
}

func (a *Account) checkResetPasswordCode(data *accountEntities.ResetCodeData) error {
	validCode, err := a.cacheRepository.Get(data.Email)
	if err != nil {
		return err
	}

	if string(validCode.Value) != data.Code {
		return errors.ErrorInvalidResetPasswordCode
	}

	return nil
}

func (a *Account) ChangePassword(accountID uuid.UUID, password string) error {
	account, err := a.accountRepository.GetByAccountID(accountID)
	if err != nil {
		return err
	}

	account.Password = password
	account.SetPasswordHash()
	_ = a.cacheRepository.Del(accountID.String())
	return a.accountRepository.Update(account)
}

func (a *Account) RenewToken(refreshToken, accessToken string) (*accountEntities.LoginResponse, error) {
	accountID, _ := jwt.GetAccountIDByJWTToken(accessToken)
	account, err := a.accountRepository.GetByAccountID(accountID)
	if err != nil {
		return nil, err
	}

	err = a.getAndValidateRefreshToken(refreshToken, accessToken, account.AccountID)
	if err != nil {
		return nil, err
	}

	_ = a.cacheRepository.Del(accountID.String())
	return a.setLoginResponse(account)
}

func (a *Account) getAndValidateRefreshToken(refreshToken, accessToken string, accountID uuid.UUID) error {
	refreshTokenValid, err := a.cacheRepository.Get(accountID.String())
	if err != nil {
		return err
	}

	if len(refreshTokenValid.Value) == 0 || string(refreshTokenValid.Value) != refreshToken {
		return errors.ErrorNotFoundRefreshTokenInCache
	}

	return a.decodeAndValidateTokens(accountID.String(), accessToken)
}

func (a *Account) decodeAndValidateTokens(accountID, accessToken string) error {
	token, err := jwt.DecodeToken(accessToken)
	if err != nil {
		return err
	}

	if accountID != token.Subject {
		return errors.ErrorAccessAndRefreshTokenNotMatch
	}

	return nil
}

func (a *Account) setLoginResponse(account *accountEntities.Account) (*accountEntities.LoginResponse, error) {
	accessToken, expiresAt, _ := a.createTokenWithAccountPermissions(account)
	refreshToken := jwt.CreateRefreshToken()
	err := a.cacheRepository.Set(
		&entityCache.Cache{Key: account.AccountID.String(), Value: []byte(refreshToken)}, time.Hour*2)
	if err != nil {
		return nil, err
	}

	return account.ToLoginResponse(accessToken, refreshToken, expiresAt), nil
}

func (a *Account) Logout(accountID uuid.UUID) error {
	account, err := a.accountRepository.GetByAccountID(accountID)
	if err != nil {
		return err
	}

	return a.cacheRepository.Del(account.AccountID.String())
}

func (a *Account) createTokenWithAccountPermissions(account *accountEntities.Account) (string, time.Time, error) {
	accountRepository, _ := a.accountRepositoryRepo.GetOfAccount(account.AccountID)
	return jwt.CreateToken(account, a.useCases.MapRepositoriesRoles(&accountRepository))
}

func (a *Account) getURLToResetPassword(email, code string) string {
	base := env.GetHorusecManagerURL()
	return fmt.Sprintf("%s/auth/recovery-password/check-code?email=%s&code=%s", base, email, code)
}

func (a *Account) VerifyAlreadyInUse(validateUnique *accountEntities.ValidateUnique) error {
	validateEmail, _ := a.accountRepository.GetByEmail(validateUnique.Email)
	if validateEmail != nil && validateEmail.Email != "" {
		return errors.ErrorEmailAlreadyInUse
	}

	validateUsername, _ := a.accountRepository.GetByUsername(validateUnique.Username)
	if validateUsername != nil && validateUsername.Username != "" {
		return errors.ErrorUsernameAlreadyInUse
	}

	return nil
}

func (a *Account) DeleteAccount(accountID uuid.UUID) error {
	account, err := a.accountRepository.GetByAccountID(accountID)
	if err != nil {
		return err
	}

	return a.accountRepository.DeleteAccount(account.AccountID)
}
