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
	"github.com/ZupIT/horusec/development-kit/pkg/utils/crypto"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"time"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccount "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	entityCache "github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/messages"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	emailEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/messages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/queues"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	"github.com/google/uuid"
)

type IAccount interface {
	CreateAccountFromKeycloak(
		keyCloakToken *dto.KeycloakToken) (*dto.CreateAccountFromKeycloakResponse, error)
	CreateAccount(account *authEntities.Account) error
	ValidateEmail(accountID uuid.UUID) error
	SendResetPasswordCode(email string) error
	VerifyResetPasswordCode(data *dto.ResetCodeData) (string, error)
	ChangePassword(accountID uuid.UUID, password string) error
	RenewToken(refreshToken, accessToken string) (*dto.LoginResponse, error)
	Logout(accountID uuid.UUID) error
	createTokenWithAccountPermissions(account *authEntities.Account) (string, time.Time, error)
	VerifyAlreadyInUse(validateUnique *dto.ValidateUnique) error
	DeleteAccount(accountID uuid.UUID) error
	GetAccountIDByEmail(email string) (uuid.UUID, error)
	GetAccountID(token string) (uuid.UUID, error)
	UpdateAccount(account *authEntities.Account) error
}

type Account struct {
	accountRepository     repositoryAccount.IAccount
	keycloakService       keycloak.IService
	broker                brokerLib.IBroker
	databaseRead          SQL.InterfaceRead
	databaseWrite         SQL.InterfaceWrite
	accountRepositoryRepo repoAccountRepository.IAccountRepository
	cacheRepository       cache.Interface
	appConfig             *app.Config
	authUseCases          authUseCases.IUseCases
	keycloak              keycloak.IService
}

func NewAccountController(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead,
	databaseWrite SQL.InterfaceWrite, cacheRepository cache.Interface, appConfig *app.Config) IAccount {
	return &Account{
		accountRepository:     repositoryAccount.NewAccountRepository(databaseRead, databaseWrite),
		keycloakService:       keycloak.NewKeycloakService(),
		broker:                broker,
		databaseWrite:         databaseWrite,
		databaseRead:          databaseRead,
		accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(databaseRead, databaseWrite),
		cacheRepository:       cacheRepository,
		appConfig:             appConfig,
		authUseCases:          authUseCases.NewAuthUseCases(),
		keycloak:              keycloak.NewKeycloakService(),
	}
}

func (a *Account) CreateAccountFromKeycloak(
	keyCloakToken *dto.KeycloakToken) (*dto.CreateAccountFromKeycloakResponse, error) {
	account, err := a.newAccountFromKeycloakToken(keyCloakToken.AccessToken)
	if err != nil {
		return nil, err
	}

	if err := a.accountRepository.Create(account); err != nil {
		return a.authUseCases.ToCreateAccountFromKeycloakResponse(account), a.authUseCases.CheckCreateAccountErrorType(err)
	}

	return a.authUseCases.ToCreateAccountFromKeycloakResponse(account), nil
}

func (a *Account) newAccountFromKeycloakToken(accessToken string) (*authEntities.Account, error) {
	userInfo, err := a.keycloakService.GetUserInfo(accessToken)
	if err != nil {
		return nil, err
	}
	if userInfo.Email == nil || userInfo.Sub == nil {
		return nil, errors.ErrorInvalidKeycloakToken
	}
	if userInfo.PreferredUsername == nil {
		userInfo.PreferredUsername = userInfo.Name
	}
	return a.authUseCases.NewAccountFromKeyCloakUserInfo(userInfo), nil
}

func (a *Account) CreateAccount(account *authEntities.Account) error {
	if a.appConfig.IsDisabledBroker() {
		account = account.SetIsConfirmed()
	}

	if err := a.accountRepository.Create(account.SetAccountData()); err != nil {
		return a.authUseCases.CheckCreateAccountErrorType(err)
	}

	return a.sendValidateAccountEmail(account)
}

func (a *Account) ValidateEmail(accountID uuid.UUID) error {
	account, err := a.accountRepository.GetByAccountID(accountID)
	if err != nil {
		return err
	}

	return a.accountRepository.Update(account.SetIsConfirmed())
}

func (a *Account) sendValidateAccountEmail(account *authEntities.Account) error {
	if a.appConfig.IsDisabledBroker() {
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
	return fmt.Sprintf("%s/api/account/validate/%s", a.appConfig.GetHorusecAPIURL(), accountID)
}

func (a *Account) SendResetPasswordCode(email string) error {
	account, err := a.accountRepository.GetByEmail(email)
	if err != nil {
		return err
	}

	code := a.authUseCases.GenerateResetPasswordCode()
	err = a.cacheRepository.Set(&entityCache.Cache{Key: email, Value: []byte(code)}, time.Minute*30)
	if err != nil {
		return err
	}

	return a.sendResetPasswordEmail(account.Email, account.Username, code)
}

func (a *Account) sendResetPasswordEmail(email, username, code string) error {
	if a.appConfig.IsDisabledBroker() {
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

func (a *Account) VerifyResetPasswordCode(data *dto.ResetCodeData) (string, error) {
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

func (a *Account) checkResetPasswordCode(data *dto.ResetCodeData) error {
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
	if err := a.checkIfPasswordHashIsEqualNewPassword(account.Password, password); err != nil {
		logger.LogError("{ACCOUNT} Error on validate password: ", err)
		return errors.ErrorInvalidPassword
	}
	account = a.setNewPasswordInAccount(account, password)
	_ = a.cacheRepository.Del(accountID.String())
	return a.accountRepository.UpdatePassword(account)
}

func (a *Account) setNewPasswordInAccount(account *authEntities.Account, password string) *authEntities.Account {
	account.Password = password
	account.SetPasswordHash()
	return account
}

func (a *Account) RenewToken(refreshToken, accessToken string) (*dto.LoginResponse, error) {
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

func (a *Account) setLoginResponse(account *authEntities.Account) (*dto.LoginResponse, error) {
	accessToken, expiresAt, _ := a.createTokenWithAccountPermissions(account)
	refreshToken := jwt.CreateRefreshToken()
	err := a.cacheRepository.Set(
		&entityCache.Cache{Key: account.AccountID.String(), Value: []byte(refreshToken)}, time.Hour*2)
	if err != nil {
		return nil, err
	}

	return a.authUseCases.ToLoginResponse(account, accessToken, refreshToken, expiresAt), nil
}

func (a *Account) Logout(accountID uuid.UUID) error {
	account, err := a.accountRepository.GetByAccountID(accountID)
	if err != nil {
		return err
	}

	return a.cacheRepository.Del(account.AccountID.String())
}

func (a *Account) createTokenWithAccountPermissions(account *authEntities.Account) (string, time.Time, error) {
	accountRepository, _ := a.accountRepositoryRepo.GetOfAccount(account.AccountID)
	return jwt.CreateToken(account, a.authUseCases.MapRepositoriesRoles(&accountRepository))
}

func (a *Account) getURLToResetPassword(email, code string) string {
	base := env.GetHorusecManagerURL()
	return fmt.Sprintf("%s/auth/recovery-password/check-code?email=%s&code=%s", base, email, code)
}

func (a *Account) VerifyAlreadyInUse(validateUnique *dto.ValidateUnique) error {
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

func (a *Account) GetAccountIDByEmail(email string) (uuid.UUID, error) {
	account, err := a.accountRepository.GetByEmail(email)
	if err != nil {
		return uuid.Nil, err
	}

	return account.AccountID, nil
}

func (a *Account) GetAccountID(token string) (uuid.UUID, error) {
	switch a.appConfig.GetAuthType() {
	case authEnums.Horusec:
		return jwt.GetAccountIDByJWTToken(token)
	case authEnums.Keycloak:
		return a.keycloak.GetAccountIDByJWTToken(token)
	case authEnums.Ldap:
		return jwt.GetAccountIDByJWTToken(token)
	}

	return uuid.Nil, errors.ErrorUnauthorized
}

func (a *Account) UpdateAccount(accountUpdate *authEntities.Account) error {
	account, err := a.accountRepository.GetByAccountID(accountUpdate.AccountID)
	if err != nil {
		return err
	}

	if accountUpdate.Username != "" {
		account.Username = accountUpdate.Username
	}

	account, err = a.handleAccountEmailChange(account, accountUpdate)
	if err != nil {
		return err
	}

	return a.accountRepository.Update(account)
}

func (a *Account) handleAccountEmailChange(
	account, accountUpdate *authEntities.Account) (*authEntities.Account, error) {
	if accountUpdate.Email != "" && account.Email != accountUpdate.Email {
		account.Email = accountUpdate.Email
		account.IsConfirmed = false
		return account, a.sendValidateAccountEmail(account)
	}

	return account, nil
}
func (a *Account) checkIfPasswordHashIsEqualNewPassword(passwordHash, newPassword string) error {
	if passwordHash == "" || newPassword == "" {
		return errors.ErrorNewPasswordOrPasswordHashNotBeEmpty
	}
	isValid := crypto.CheckPasswordHash(newPassword, passwordHash)
	if isValid {
		return errors.ErrorNewPasswordNotEqualOldPassword
	}
	return nil
}
