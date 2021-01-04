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
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v7"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewCredentialsFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to credentials", func(t *testing.T) {
		bytes, _ := json.Marshal(&dto.Credentials{
			Username: "test",
			Password: "test",
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		credentials, err := useCases.NewCredentialsFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, credentials)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewAuthUseCases()
		_, err := useCases.NewCredentialsFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestNewAuthorizationDataFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to authorization data", func(t *testing.T) {
		bytes, _ := json.Marshal(&dto.AuthorizationData{
			Token: "test",
			Role:  authEnums.RepositoryAdmin,
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		credentials, err := useCases.NewAuthorizationDataFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, credentials)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewAuthUseCases()
		_, err := useCases.NewAuthorizationDataFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestIsInvalidAuthType(t *testing.T) {
	t.Run("should return true when invalid type", func(t *testing.T) {
		useCases := NewAuthUseCases()
		isInvalid := useCases.IsInvalidAuthType(authEnums.Keycloak)
		assert.Error(t, isInvalid)

		isInvalid = useCases.IsInvalidAuthType(authEnums.Ldap)
		assert.Error(t, isInvalid)

		isInvalid = useCases.IsInvalidAuthType("test")
		assert.Error(t, isInvalid)
	})

	t.Run("should false when valid", func(t *testing.T) {
		useCases := NewAuthUseCases()
		isInvalid := useCases.IsInvalidAuthType(authEnums.Horusec)
		assert.NoError(t, isInvalid)
	})
}

func TestToLoginResponse(t *testing.T) {
	t.Run("should success parse to login response", func(t *testing.T) {
		useCases := NewAuthUseCases()

		account := &authEntities.Account{
			AccountID:   uuid.New(),
			Email:       "test",
			Password:    "test",
			Username:    "test",
			IsConfirmed: false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		assert.NotEmpty(t, useCases.ToLoginResponse(account, "test", "test", time.Now()))
	})
}

func TestToCreateAccountFromKeycloakResponse(t *testing.T) {
	t.Run("should success parse to create account from keycloak response", func(t *testing.T) {
		useCases := NewAuthUseCases()

		account := &authEntities.Account{
			AccountID:          uuid.New(),
			Username:           uuid.New().String(),
			Email:              uuid.New().String(),
			IsApplicationAdmin: true,
		}

		assert.NotEmpty(t, useCases.ToCreateAccountFromKeycloakResponse(account))
	})
}

func TestValidateLogin(t *testing.T) {
	t.Run("should return no errors when valid data", func(t *testing.T) {
		account := &authEntities.Account{
			Email:       "test@test.com",
			Username:    "test",
			AccountID:   uuid.New(),
			IsConfirmed: true,
			Password:    "$2a$10$sjCTUO0VLAxW10KwRXAIn.lLuDtUf8xqZHy9CrmJLd77Ief4J21yS",
		}

		loginData := &dto.LoginData{
			Email:    "test@test.com",
			Password: "2131231",
		}

		useCases := NewAuthUseCases()
		err := useCases.ValidateLogin(account, loginData)
		assert.NoError(t, err)
	})

	t.Run("should return no error when email it is not confirmed", func(t *testing.T) {
		account := &authEntities.Account{
			Email:       "test@test.com",
			Username:    "test",
			AccountID:   uuid.New(),
			IsConfirmed: false,
			Password:    "$2a$10$sjCTUO0VLAxW10KwRXAIn.lLuDtUf8xqZHy9CrmJLd77Ief4J21yS",
		}

		loginData := &dto.LoginData{
			Email:    "test@test.com",
			Password: "2131231",
		}

		useCases := NewAuthUseCases()
		err := useCases.ValidateLogin(account, loginData)
		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorAccountEmailNotConfirmed, err)
	})

	t.Run("should return error when invalid password", func(t *testing.T) {
		account := &authEntities.Account{
			Email:       "test@test.com",
			Username:    "test",
			AccountID:   uuid.New(),
			IsConfirmed: true,
			Password:    "$2a$10$sjCTUO0VLAxW10KwRXAIn.lLuDtUf8xqZHy9CrmJLd77Ief4J21yS",
		}

		loginData := &dto.LoginData{
			Email:    "test@test.com",
			Password: "123",
		}

		useCases := NewAuthUseCases()
		err := useCases.ValidateLogin(account, loginData)
		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorWrongEmailOrPassword, err)
	})
}

func TestCheckCreateAccountErrorType(t *testing.T) {
	t.Run("should return error email already in use", func(t *testing.T) {
		useCases := NewAuthUseCases()
		err := errors.New("pq: duplicate key value violates unique constraint \"accounts_email_key\"")
		result := useCases.CheckCreateAccountErrorType(err)
		assert.Error(t, result)
		assert.Equal(t, errorsEnums.ErrorEmailAlreadyInUse, result)
	})

	t.Run("should return error when it is not duplicated email", func(t *testing.T) {
		useCases := NewAuthUseCases()
		err := errors.New("test")
		result := useCases.CheckCreateAccountErrorType(err)
		assert.Error(t, result)
	})

	t.Run("should return error username already in use", func(t *testing.T) {
		useCases := NewAuthUseCases()
		err := errors.New("pq: duplicate key value violates unique constraint \"uk_accounts_username\"")
		result := useCases.CheckCreateAccountErrorType(err)
		assert.Error(t, result)
		assert.Equal(t, errorsEnums.ErrorUsernameAlreadyInUse, result)
	})

	t.Run("should return error username already in use", func(t *testing.T) {
		useCases := NewAuthUseCases()
		err := errors.New("pq: duplicate key value violates unique constraint \"accounts_pkey\"")
		result := useCases.CheckCreateAccountErrorType(err)
		assert.Error(t, result)
		assert.Equal(t, errorsEnums.ErrorUsernameAlreadyInUse, result)
	})
}

func TestNewAccountFromKeyCloakUserInfo(t *testing.T) {
	t.Run("should create a new account from keycloak user info", func(t *testing.T) {
		accountId := uuid.New().String()
		email := "test@test.com"
		username := "test"

		userInfo := &gocloak.UserInfo{
			Sub:               &accountId,
			PreferredUsername: &username,
			Email:             &email,
		}

		useCases := NewAuthUseCases()

		account := useCases.NewAccountFromKeyCloakUserInfo(userInfo)

		assert.NotEmpty(t, account)
	})
}

func TestValidateEmail(t *testing.T) {
	t.Run("should return no error when valid email", func(t *testing.T) {
		useCases := NewAuthUseCases()
		useCases.GenerateResetPasswordCode()
		err := useCases.ValidateEmail("test@test.com")
		assert.NoError(t, err)
	})

	t.Run("should return no error when invalid email", func(t *testing.T) {
		useCases := NewAuthUseCases()
		useCases.GenerateResetPasswordCode()
		err := useCases.ValidateEmail("")
		assert.Error(t, err)
	})
}

func TestGenerateResetPasswordCode(t *testing.T) {
	t.Run("should success generate a random string with six chars", func(t *testing.T) {
		useCases := NewAuthUseCases()
		useCases.GenerateResetPasswordCode()
		result := useCases.GenerateResetPasswordCode()
		assert.NotEmpty(t, result)
		assert.Len(t, result, 6)
	})
}

func TestNewKeycloakTokenFromReadCloser(t *testing.T) {
	t.Run("should parse and return no error when valid token", func(t *testing.T) {
		bytes, _ := json.Marshal(&dto.KeycloakToken{AccessToken: "test"})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		_, err := useCases.NewKeycloakTokenFromReadCloser(readCloser)
		assert.NoError(t, err)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		useCases := NewAuthUseCases()

		readCloser := ioutil.NopCloser(strings.NewReader("test"))

		_, err := useCases.NewKeycloakTokenFromReadCloser(readCloser)
		assert.Error(t, err)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		useCases := NewAuthUseCases()
		_, err := useCases.NewKeycloakTokenFromReadCloser(nil)
		assert.Error(t, err)
	})
}

func TestNewValidateUniqueFromReadCloser(t *testing.T) {
	t.Run("should return no error when validate unique is valid", func(t *testing.T) {
		bytes, _ := json.Marshal(dto.ValidateUnique{Email: "test@test.com", Username: "test"})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		result, err := useCases.NewValidateUniqueFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, "test", result.Username)
		assert.Equal(t, "test@test.com", result.Email)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewAuthUseCases()
		_, err := useCases.NewValidateUniqueFromReadCloser(readCloser)
		assert.Error(t, err)
	})

	t.Run("should return error when nil body", func(t *testing.T) {
		useCases := NewAuthUseCases()
		_, err := useCases.NewValidateUniqueFromReadCloser(nil)
		assert.Error(t, err)
	})
}

func TestNewPasswordFromReadCloser(t *testing.T) {
	t.Run("should return required value when valid password", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))

		useCases := NewAuthUseCases()
		_, err := useCases.NewPasswordFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Equal(t, "cannot be blank", err.Error())
	})
	t.Run("should return not valid length when valid password", func(t *testing.T) {
		bytes, _ := json.Marshal("@t3st")
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		_, err := useCases.NewPasswordFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Equal(t, "the length must be between 8 and 255", err.Error())
	})
	t.Run("should return not valid upper case when valid password", func(t *testing.T) {
		bytes, _ := json.Marshal("teesstee")
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		_, err := useCases.NewPasswordFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Equal(t, "must be a character upper case", err.Error())
	})
	t.Run("should return not valid number when valid password", func(t *testing.T) {
		bytes, _ := json.Marshal("teesstEE")
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		_, err := useCases.NewPasswordFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Equal(t, "must be a character digit", err.Error())
	})
	t.Run("should return not valid special when valid password", func(t *testing.T) {
		bytes, _ := json.Marshal("t33sstEE")
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		_, err := useCases.NewPasswordFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Equal(t, "must be a character special", err.Error())
	})
	t.Run("should validate with success", func(t *testing.T) {
		bytes, _ := json.Marshal("@t33sstEE")
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		password, err := useCases.NewPasswordFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, "\"@t33sstEE\"", password)
	})
	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		useCases := NewAuthUseCases()
		_, err := useCases.NewPasswordFromReadCloser(nil)
		assert.Error(t, err)
	})
}

func TestNewResetCodeDataFromReadCloser(t *testing.T) {
	data := &dto.ResetCodeData{
		Email: "test@test.com",
		Code:  "W13e4q",
	}

	t.Run("should return reset code data from read closer", func(t *testing.T) {
		bytes, _ := json.Marshal(data)
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		resetCodeData, err := useCases.NewResetCodeDataFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, data, resetCodeData)
	})

	t.Run("should return error when invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader("test"))

		useCases := NewAuthUseCases()
		_, err := useCases.NewResetCodeDataFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestNewEmailDataFromReadCloser(t *testing.T) {
	data := &dto.EmailData{
		Email: "test@test.com",
	}

	t.Run("should return email data from read closer", func(t *testing.T) {
		bytes, _ := json.Marshal(data)
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		emailData, err := useCases.NewEmailDataFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, data, emailData)
	})

	t.Run("should return error when invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader("test"))

		useCases := NewAuthUseCases()
		_, err := useCases.NewEmailDataFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestNewRefreshTokenFromReadCloser(t *testing.T) {
	t.Run("should return no error when valid token", func(t *testing.T) {
		bytes, _ := json.Marshal("t3st3c")
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		token, err := useCases.NewRefreshTokenFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, "\"t3st3c\"", token)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		useCases := NewAuthUseCases()
		_, err := useCases.NewRefreshTokenFromReadCloser(nil)
		assert.Error(t, err)
	})
}

func TestNewAccountFromReadCloser(t *testing.T) {
	t.Run("should return required value when valid password", func(t *testing.T) {
		bytes, _ := json.Marshal(&authEntities.Account{
			Email:     "test@test.com",
			Username:  "test",
			Password:  "",
			AccountID: uuid.New(),
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		_, err := useCases.NewAccountFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Equal(t, "password: cannot be blank.", err.Error())
	})
	t.Run("should return not valid length when valid password", func(t *testing.T) {
		bytes, _ := json.Marshal(&authEntities.Account{
			Email:     "test@test.com",
			Username:  "test",
			Password:  "@tEst12",
			AccountID: uuid.New(),
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		_, err := useCases.NewAccountFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Equal(t, "password: the length must be between 8 and 255.", err.Error())
	})
	t.Run("should return not valid upper case when valid password", func(t *testing.T) {
		bytes, _ := json.Marshal(&authEntities.Account{
			Email:     "test@test.com",
			Username:  "test",
			Password:  "teesstee",
			AccountID: uuid.New(),
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		_, err := useCases.NewAccountFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Equal(t, "password: must be a character upper case.", err.Error())
	})
	t.Run("should return not valid number when valid password", func(t *testing.T) {
		bytes, _ := json.Marshal(&authEntities.Account{
			Email:     "test@test.com",
			Username:  "test",
			Password:  "teesstEE",
			AccountID: uuid.New(),
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		_, err := useCases.NewAccountFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Equal(t, "password: must be a character digit.", err.Error())
	})
	t.Run("should return not valid special when valid password", func(t *testing.T) {
		bytes, _ := json.Marshal(&authEntities.Account{
			Email:     "test@test.com",
			Username:  "test",
			Password:  "t33sstEE",
			AccountID: uuid.New(),
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		_, err := useCases.NewAccountFromReadCloser(readCloser)
		assert.Error(t, err)
		assert.Equal(t, "password: must be a character special.", err.Error())
	})
	t.Run("should validate with success", func(t *testing.T) {
		bytes, _ := json.Marshal(&authEntities.Account{
			Email:     "test@test.com",
			Username:  "test",
			Password:  "@t33sstEE",
			AccountID: uuid.New(),
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAuthUseCases()
		account, err := useCases.NewAccountFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, "@t33sstEE", account.Password)
		assert.Equal(t, "test@test.com", account.Email)
		assert.Equal(t, "test", account.Username)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewAuthUseCases()
		_, err := useCases.NewAccountFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}
