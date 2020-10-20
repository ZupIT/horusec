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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"time"

	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type IAccount interface {
	NewAccountFromReadCloser(body io.ReadCloser) (account *accountEntities.Account, err error)
	NewLoginFromReadCloser(body io.ReadCloser) (loginData *accountEntities.LoginData, err error)
	ValidateLogin(account *accountEntities.Account, loginData *accountEntities.LoginData) error
	CheckCreateAccountErrorType(err error) error
	GenerateResetPasswordCode() string
	ValidateEmail(email string) error
	ValidateResetPasswordCode(validCode []byte, informedCode string) error
	NewResetCodeDataFromReadCloser(body io.ReadCloser) (data *accountEntities.ResetCodeData, err error)
	NewPasswordFromReadCloser(body io.ReadCloser) (password string, err error)
	NewEmailDataFromReadCloser(body io.ReadCloser) (data *accountEntities.EmailData, err error)
	MapRepositoriesRoles(accountRepositories *[]roles.AccountRepository) map[string]string
	NewRefreshTokenFromReadCloser(body io.ReadCloser) (token string, err error)
	NewValidateUniqueFromReadCloser(body io.ReadCloser) (validateUnique *accountEntities.ValidateUnique, err error)
	NewKeycloakTokenFromReadCloser(body io.ReadCloser) (*accountEntities.KeycloakToken, error)
}

type Account struct {
}

func NewAccountUseCases() IAccount {
	return &Account{}
}

func (a *Account) NewAccountFromReadCloser(body io.ReadCloser) (*accountEntities.Account, error) {
	createAccount := &accountEntities.CreateAccount{}
	err := json.NewDecoder(body).Decode(&createAccount)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	account := createAccount.ToAccount()
	return account, account.Validate()
}

func (a *Account) NewLoginFromReadCloser(body io.ReadCloser) (loginData *accountEntities.LoginData, err error) {
	err = json.NewDecoder(body).Decode(&loginData)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return loginData, loginData.Validate()
}

func (a *Account) ValidateLogin(account *accountEntities.Account, loginData *accountEntities.LoginData) error {
	if loginData.IsInvalid(account.Email, account.Password) {
		return errors.ErrorWrongEmailOrPassword
	}

	return account.IsAccountConfirmed()
}

func (a *Account) CheckCreateAccountErrorType(err error) error {
	if err.Error() == "pq: duplicate key value violates unique constraint \"accounts_email_key\"" {
		return errors.ErrorEmailAlreadyInUse
	}

	if err.Error() == "pq: duplicate key value violates unique constraint \"uk_accounts_username\"" {
		return errors.ErrorUsernameAlreadyInUse
	}

	if err.Error() == "pq: duplicate key value violates unique constraint \"accounts_pkey\"" {
		return errors.ErrorUsernameAlreadyInUse
	}

	return err
}

func (a *Account) GenerateResetPasswordCode() string {
	const charset = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := make([]byte, 6)
	for i := range code {
		code[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(code)
}

func (a *Account) ValidateEmail(email string) error {
	return validation.Validate(email, validation.Required, validation.Length(1, 255), is.Email)
}

func (a *Account) NewResetCodeDataFromReadCloser(body io.ReadCloser) (data *accountEntities.ResetCodeData, err error) {
	err = json.NewDecoder(body).Decode(&data)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return data, data.Validate()
}

func (a *Account) ValidateResetPasswordCode(validCode []byte, informedCode string) error {
	if string(validCode) != informedCode {
		return errors.ErrorInvalidResetPasswordCode
	}

	return nil
}

func (a *Account) NewPasswordFromReadCloser(body io.ReadCloser) (password string, err error) {
	if body == nil {
		return "", errors.ErrorErrorEmptyBody
	}

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(body)
	password = buf.String()

	return password, validation.Validate(password, validation.Required, validation.Length(1, 255))
}

func (a *Account) NewEmailDataFromReadCloser(body io.ReadCloser) (data *accountEntities.EmailData, err error) {
	err = json.NewDecoder(body).Decode(&data)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return data, a.ValidateEmail(data.Email)
}

func (a *Account) MapRepositoriesRoles(accountRepositories *[]roles.AccountRepository) map[string]string {
	m := make(map[string]string)
	if accountRepositories == nil {
		return m
	}

	for _, accountRepository := range *accountRepositories {
		m[accountRepository.RepositoryID.String()] = fmt.Sprint(accountRepository.Role)
	}

	return m
}

func (a *Account) NewRefreshTokenFromReadCloser(body io.ReadCloser) (token string, err error) {
	if body == nil {
		return "", errors.ErrorErrorEmptyBody
	}

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(body)
	token = buf.String()

	return token, validation.Validate(token, validation.Required, validation.Length(1, 255))
}

func (a *Account) NewValidateUniqueFromReadCloser(
	body io.ReadCloser) (validateUnique *accountEntities.ValidateUnique, err error) {
	err = json.NewDecoder(body).Decode(&validateUnique)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return validateUnique, validateUnique.Validate()
}

func (a *Account) NewKeycloakTokenFromReadCloser(body io.ReadCloser) (*accountEntities.KeycloakToken, error) {
	keycloakToken := &accountEntities.KeycloakToken{}
	err := json.NewDecoder(body).Decode(&keycloakToken)
	_ = body.Close()
	if err != nil {
		return nil, err
	}
	return keycloakToken, keycloakToken.Validate()
}
