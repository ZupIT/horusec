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
	"encoding/json"
	"errors"
	"github.com/Nerzal/gocloak/v7"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"
)

func TestNewAccountFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to account", func(t *testing.T) {
		bytes, _ := json.Marshal(&accountEntities.Account{
			Email:     "test@test.com",
			Username:  "test",
			Password:  "test",
			AccountID: uuid.New(),
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAccountUseCases()
		account, err := useCases.NewAccountFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, account)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewAccountUseCases()
		_, err := useCases.NewAccountFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestNewLoginFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to login data", func(t *testing.T) {
		bytes, _ := json.Marshal(&accountEntities.LoginData{
			Email:    "test@test.com",
			Password: "test",
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAccountUseCases()
		loginData, err := useCases.NewLoginFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, loginData)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewAccountUseCases()
		_, err := useCases.NewLoginFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestValidateLogin(t *testing.T) {
	t.Run("should return no errors when valid data", func(t *testing.T) {
		account := &accountEntities.Account{
			Email:       "test@test.com",
			Username:    "test",
			AccountID:   uuid.New(),
			IsConfirmed: true,
			Password:    "$2a$10$sjCTUO0VLAxW10KwRXAIn.lLuDtUf8xqZHy9CrmJLd77Ief4J21yS",
		}

		loginData := &accountEntities.LoginData{
			Email:    "test@test.com",
			Password: "2131231",
		}

		useCases := NewAccountUseCases()
		err := useCases.ValidateLogin(account, loginData)
		assert.NoError(t, err)
	})

	t.Run("should return no error when email it is not confirmed", func(t *testing.T) {
		account := &accountEntities.Account{
			Email:       "test@test.com",
			Username:    "test",
			AccountID:   uuid.New(),
			IsConfirmed: false,
			Password:    "$2a$10$sjCTUO0VLAxW10KwRXAIn.lLuDtUf8xqZHy9CrmJLd77Ief4J21yS",
		}

		loginData := &accountEntities.LoginData{
			Email:    "test@test.com",
			Password: "2131231",
		}

		useCases := NewAccountUseCases()
		err := useCases.ValidateLogin(account, loginData)
		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorAccountEmailNotConfirmed, err)
	})

	t.Run("should return error when invalid password", func(t *testing.T) {
		account := &accountEntities.Account{
			Email:       "test@test.com",
			Username:    "test",
			AccountID:   uuid.New(),
			IsConfirmed: true,
			Password:    "$2a$10$sjCTUO0VLAxW10KwRXAIn.lLuDtUf8xqZHy9CrmJLd77Ief4J21yS",
		}

		loginData := &accountEntities.LoginData{
			Email:    "test@test.com",
			Password: "123",
		}

		useCases := NewAccountUseCases()
		err := useCases.ValidateLogin(account, loginData)
		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorWrongEmailOrPassword, err)
	})
}

func TestCheckCreateAccountErrorType(t *testing.T) {
	t.Run("should return error email already in use", func(t *testing.T) {
		useCases := NewAccountUseCases()
		err := errors.New("pq: duplicate key value violates unique constraint \"accounts_email_key\"")
		result := useCases.CheckCreateAccountErrorType(err)
		assert.Error(t, result)
		assert.Equal(t, errorsEnums.ErrorEmailAlreadyInUse, result)
	})

	t.Run("should return error when it is not duplicated email", func(t *testing.T) {
		useCases := NewAccountUseCases()
		err := errors.New("test")
		result := useCases.CheckCreateAccountErrorType(err)
		assert.Error(t, result)
	})

	t.Run("should return error username already in use", func(t *testing.T) {
		useCases := NewAccountUseCases()
		err := errors.New("pq: duplicate key value violates unique constraint \"uk_accounts_username\"")
		result := useCases.CheckCreateAccountErrorType(err)
		assert.Error(t, result)
		assert.Equal(t, errorsEnums.ErrorUsernameAlreadyInUse, result)
	})

	t.Run("should return error username already in use", func(t *testing.T) {
		useCases := NewAccountUseCases()
		err := errors.New("pq: duplicate key value violates unique constraint \"accounts_pkey\"")
		result := useCases.CheckCreateAccountErrorType(err)
		assert.Error(t, result)
		assert.Equal(t, errorsEnums.ErrorUsernameAlreadyInUse, result)
	})
}

func TestGenerateResetPasswordCode(t *testing.T) {
	t.Run("should success generate a random string with six chars", func(t *testing.T) {
		useCases := NewAccountUseCases()
		useCases.GenerateResetPasswordCode()
		result := useCases.GenerateResetPasswordCode()
		assert.NotEmpty(t, result)
		assert.Len(t, result, 6)
	})
}

func TestValidateEmail(t *testing.T) {
	t.Run("should return no error when valid email", func(t *testing.T) {
		useCases := NewAccountUseCases()
		useCases.GenerateResetPasswordCode()
		err := useCases.ValidateEmail("test@test.com")
		assert.NoError(t, err)
	})

	t.Run("should return no error when invalid email", func(t *testing.T) {
		useCases := NewAccountUseCases()
		useCases.GenerateResetPasswordCode()
		err := useCases.ValidateEmail("")
		assert.Error(t, err)
	})
}

func TestValidateResetPasswordCode(t *testing.T) {
	t.Run("should return no error when valid code", func(t *testing.T) {
		useCases := NewAccountUseCases()
		err := useCases.ValidateResetPasswordCode([]byte("test"), "test")
		assert.NoError(t, err)
	})

	t.Run("should return error when invalid code", func(t *testing.T) {
		useCases := NewAccountUseCases()
		err := useCases.ValidateResetPasswordCode([]byte("test"), "123456")
		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorInvalidResetPasswordCode, err)
	})
}

func TestNewPasswordFromReadCloser(t *testing.T) {
	t.Run("should return no error when valid password", func(t *testing.T) {
		bytes, _ := json.Marshal("t3st3c")
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAccountUseCases()
		password, err := useCases.NewPasswordFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, "\"t3st3c\"", password)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		useCases := NewAccountUseCases()
		_, err := useCases.NewPasswordFromReadCloser(nil)
		assert.Error(t, err)
	})
}

func TestNewResetCodeDataFromReadCloser(t *testing.T) {
	data := &accountEntities.ResetCodeData{
		Email: "test@test.com",
		Code:  "W13e4q",
	}

	t.Run("should return reset code data from read closer", func(t *testing.T) {
		bytes, _ := json.Marshal(data)
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAccountUseCases()
		resetCodeData, err := useCases.NewResetCodeDataFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, data, resetCodeData)
	})

	t.Run("should return error when invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader("test"))

		useCases := NewAccountUseCases()
		_, err := useCases.NewResetCodeDataFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestNewEmailDataFromReadCloser(t *testing.T) {
	data := &accountEntities.EmailData{
		Email: "test@test.com",
	}

	t.Run("should return email data from read closer", func(t *testing.T) {
		bytes, _ := json.Marshal(data)
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAccountUseCases()
		emailData, err := useCases.NewEmailDataFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, data, emailData)
	})

	t.Run("should return error when invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader("test"))

		useCases := NewAccountUseCases()
		_, err := useCases.NewEmailDataFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}
func TestMapRepositoriesRoles(t *testing.T) {
	t.Run("should map a accountRepository role with the", func(t *testing.T) {
		repositoryID := uuid.New()
		accountRepositories := &[]roles.AccountRepository{{
			RepositoryID: repositoryID,
			Role:         "admin",
		}}

		useCases := NewAccountUseCases()
		mappedRoles := useCases.MapRepositoriesRoles(accountRepositories)
		assert.NotEmpty(t, mappedRoles)
		assert.Equal(t, mappedRoles[repositoryID.String()], "admin")
	})

	t.Run("should return empty map when nil repository", func(t *testing.T) {
		useCases := NewAccountUseCases()
		mappedRoles := useCases.MapRepositoriesRoles(nil)
		assert.Empty(t, mappedRoles)
	})
}

func TestNewRefreshTokenFromReadCloser(t *testing.T) {
	t.Run("should return no error when valid token", func(t *testing.T) {
		bytes, _ := json.Marshal("t3st3c")
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAccountUseCases()
		token, err := useCases.NewRefreshTokenFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, "\"t3st3c\"", token)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		useCases := NewAccountUseCases()
		_, err := useCases.NewRefreshTokenFromReadCloser(nil)
		assert.Error(t, err)
	})
}

func TestNewValidateUniqueFromReadCloser(t *testing.T) {
	t.Run("should return no error when validate unique is valid", func(t *testing.T) {
		bytes, _ := json.Marshal(accountEntities.ValidateUnique{Email: "test@test.com", Username: "test"})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAccountUseCases()
		result, err := useCases.NewValidateUniqueFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.Equal(t, "test", result.Username)
		assert.Equal(t, "test@test.com", result.Email)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewAccountUseCases()
		_, err := useCases.NewValidateUniqueFromReadCloser(readCloser)
		assert.Error(t, err)
	})

	t.Run("should return error when nil body", func(t *testing.T) {
		useCases := NewAccountUseCases()
		_, err := useCases.NewValidateUniqueFromReadCloser(nil)
		assert.Error(t, err)
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

		useCases := NewAccountUseCases()

		account := useCases.NewAccountFromKeyCloakUserInfo(userInfo)

		assert.NotEmpty(t, account)
	})
}

func TestNewKeycloakTokenFromReadCloser(t *testing.T) {
	t.Run("should parse and return no error when valid token", func(t *testing.T) {
		bytes, _ := json.Marshal(&accountEntities.KeycloakToken{AccessToken: "test"})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewAccountUseCases()
		_, err := useCases.NewKeycloakTokenFromReadCloser(readCloser)
		assert.NoError(t, err)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		useCases := NewAccountUseCases()

		readCloser := ioutil.NopCloser(strings.NewReader("test"))

		_, err := useCases.NewKeycloakTokenFromReadCloser(readCloser)
		assert.Error(t, err)
	})

	t.Run("should return error when parsing invalid data", func(t *testing.T) {
		useCases := NewAccountUseCases()
		_, err := useCases.NewKeycloakTokenFromReadCloser(nil)
		assert.Error(t, err)
	})
}
