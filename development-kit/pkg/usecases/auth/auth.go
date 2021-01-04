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

package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"regexp"
	"time"

	"github.com/Nerzal/gocloak/v7"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
)

type IUseCases interface {
	NewCredentialsFromReadCloser(body io.ReadCloser) (*dto.Credentials, error)
	NewAuthorizationDataFromReadCloser(body io.ReadCloser) (*dto.AuthorizationData, error)
	IsInvalidAuthType(authType authEnums.AuthorizationType) error
	ToLoginResponse(
		account *authEntities.Account, accessToken, refreshToken string, expiresAt time.Time) *dto.LoginResponse
	ToCreateAccountFromKeycloakResponse(account *authEntities.Account) *dto.CreateAccountFromKeycloakResponse
	ValidateLogin(account *authEntities.Account, loginData *dto.LoginData) error
	CheckCreateAccountErrorType(err error) error
	NewAccountFromKeyCloakUserInfo(userInfo *gocloak.UserInfo) *authEntities.Account
	GenerateResetPasswordCode() string
	ValidateEmail(email string) error
	NewKeycloakTokenFromReadCloser(body io.ReadCloser) (*dto.KeycloakToken, error)
	NewAccountFromReadCloser(body io.ReadCloser) (*authEntities.Account, error)
	NewEmailDataFromReadCloser(body io.ReadCloser) (data *dto.EmailData, err error)
	NewResetCodeDataFromReadCloser(body io.ReadCloser) (data *dto.ResetCodeData, err error)
	NewPasswordFromReadCloser(body io.ReadCloser) (password string, err error)
	NewRefreshTokenFromReadCloser(body io.ReadCloser) (token string, err error)
	NewValidateUniqueFromReadCloser(body io.ReadCloser) (validateUnique *dto.ValidateUnique, err error)
	NewAccountUpdateFromReadCloser(body io.ReadCloser) (*authEntities.Account, error)
}

const DefaultRegexPasswordValidation = ""

type UseCases struct {
}

func NewAuthUseCases() IUseCases {
	return &UseCases{}
}

func (u *UseCases) NewCredentialsFromReadCloser(body io.ReadCloser) (*dto.Credentials, error) {
	credentials := &dto.Credentials{}
	err := json.NewDecoder(body).Decode(&credentials)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return credentials, credentials.Validate()
}

func (u *UseCases) NewAuthorizationDataFromReadCloser(body io.ReadCloser) (*dto.AuthorizationData, error) {
	authorizationData := &dto.AuthorizationData{}
	err := json.NewDecoder(body).Decode(&authorizationData)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return authorizationData, authorizationData.Validate()
}

func (u *UseCases) IsInvalidAuthType(authType authEnums.AuthorizationType) error {
	validType := env.GetEnvOrDefault("HORUSEC_AUTH_TYPE", authEnums.Horusec.ToString())
	if authType.ToString() != validType {
		return fmt.Errorf(errors.ErrorAuthTypeNotActive, validType)
	}

	return nil
}

func (u *UseCases) ToLoginResponse(account *authEntities.Account, accessToken, refreshToken string,
	expiresAt time.Time) *dto.LoginResponse {
	return &dto.LoginResponse{
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		ExpiresAt:          expiresAt,
		Username:           account.Username,
		IsApplicationAdmin: account.IsApplicationAdmin,
		Email:              account.Email,
	}
}

func (u *UseCases) ToCreateAccountFromKeycloakResponse(
	account *authEntities.Account) *dto.CreateAccountFromKeycloakResponse {
	return &dto.CreateAccountFromKeycloakResponse{
		AccountID:          account.AccountID,
		Username:           account.Username,
		Email:              account.Email,
		IsApplicationAdmin: account.IsApplicationAdmin,
	}
}

func (u *UseCases) ValidateLogin(account *authEntities.Account, loginData *dto.LoginData) error {
	if loginData.IsInvalid(account.Email, account.Password) {
		return errors.ErrorWrongEmailOrPassword
	}

	return account.IsAccountConfirmed()
}

func (u *UseCases) CheckCreateAccountErrorType(err error) error {
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

func (u *UseCases) NewAccountFromKeyCloakUserInfo(userInfo *gocloak.UserInfo) *authEntities.Account {
	accountID, _ := uuid.Parse(*userInfo.Sub)
	return &authEntities.Account{
		AccountID:   accountID,
		Email:       *userInfo.Email,
		Username:    *userInfo.PreferredUsername,
		CreatedAt:   time.Now(),
		IsConfirmed: true,
	}
}

func (u *UseCases) GenerateResetPasswordCode() string {
	const charset = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := make([]byte, 6)
	for i := range code {
		code[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(code)
}

func (u *UseCases) ValidateEmail(email string) error {
	return validation.Validate(email, validation.Required, validation.Length(1, 255), is.Email)
}

func (u *UseCases) NewKeycloakTokenFromReadCloser(body io.ReadCloser) (*dto.KeycloakToken, error) {
	if body == nil {
		return &dto.KeycloakToken{}, errors.ErrorErrorEmptyBody
	}
	keycloakToken := &dto.KeycloakToken{}
	err := json.NewDecoder(body).Decode(&keycloakToken)
	_ = body.Close()
	if err != nil {
		return nil, err
	}
	return keycloakToken, keycloakToken.Validate()
}

func (u *UseCases) NewAccountFromReadCloser(body io.ReadCloser) (*authEntities.Account, error) {
	createAccount := &dto.CreateAccount{}
	err := json.NewDecoder(body).Decode(&createAccount)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	account := createAccount.ToAccount()
	return account, validation.ValidateStruct(account,
		validation.Field(&account.Email, validation.Required, validation.Length(1, 255), is.Email),
		validation.Field(&account.Password, u.getPasswordValidation()...),
		validation.Field(&account.Username, validation.Length(1, 255), validation.Required),
	)
}

func (u *UseCases) NewAccountUpdateFromReadCloser(body io.ReadCloser) (*authEntities.Account, error) {
	updateAccount := &dto.UpdateAccount{}
	err := json.NewDecoder(body).Decode(&updateAccount)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	account := updateAccount.ToAccount()
	return account, account.UpdationValidate()
}

func (u *UseCases) NewEmailDataFromReadCloser(body io.ReadCloser) (data *dto.EmailData, err error) {
	err = json.NewDecoder(body).Decode(&data)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return data, u.ValidateEmail(data.Email)
}

func (u *UseCases) NewResetCodeDataFromReadCloser(body io.ReadCloser) (data *dto.ResetCodeData, err error) {
	err = json.NewDecoder(body).Decode(&data)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return data, data.Validate()
}

func (u *UseCases) NewPasswordFromReadCloser(body io.ReadCloser) (password string, err error) {
	if body == nil {
		return "", errors.ErrorErrorEmptyBody
	}
	defer func() { _ = body.Close() }()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(body)
	if err != nil {
		return "", err
	}
	password = buf.String()
	return password, validation.Validate(password, u.getPasswordValidation()...)
}

func (u *UseCases) getPasswordValidation() []validation.Rule {
	return []validation.Rule{
		validation.Required,
		validation.Length(8, 255),
		validation.Match(regexp.MustCompile(`[A-Z]`)).Error("must be a character upper case"),
		validation.Match(regexp.MustCompile(`[a-z]`)).Error("must be a character lower case"),
		validation.Match(regexp.MustCompile(`[0-9]`)).Error("must be a character digit"),
		validation.Match(regexp.MustCompile(`[!@#$&*-._]`)).Error("must be a character special"),
	}
}

func (u *UseCases) NewRefreshTokenFromReadCloser(body io.ReadCloser) (token string, err error) {
	if body == nil {
		return "", errors.ErrorErrorEmptyBody
	}

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(body)
	token = buf.String()

	return token, validation.Validate(token, validation.Required, validation.Length(1, 255))
}

func (u *UseCases) NewValidateUniqueFromReadCloser(
	body io.ReadCloser) (validateUnique *dto.ValidateUnique, err error) {
	if body == nil {
		return &dto.ValidateUnique{}, errors.ErrorErrorEmptyBody
	}
	err = json.NewDecoder(body).Decode(&validateUnique)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return validateUnique, validateUnique.Validate()
}
