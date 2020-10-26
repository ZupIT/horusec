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
	"errors"
	"os"
	"testing"
	"time"

	entityCache "github.com/ZupIT/horusec/development-kit/pkg/entities/cache"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestMock(t *testing.T) {
	controllerMock := &Mock{}
	controllerMock.On("CreateAccount").Return(nil)
	controllerMock.On("CreateAccountFromKeycloak").Return(nil)
	controllerMock.On("Login").Return(&accountEntities.LoginResponse{}, nil)
	controllerMock.On("ValidateEmail").Return(nil)
	controllerMock.On("SendResetPasswordCode").Return(nil)
	controllerMock.On("VerifyResetPasswordCode").Return("", nil)
	controllerMock.On("ChangePassword").Return(nil)
	controllerMock.On("RenewToken").Return(&accountEntities.LoginResponse{}, nil)
	controllerMock.On("Logout").Return(nil)
	controllerMock.On("createTokenWithAccountPermissions").Return("", time.Now(), nil)
	controllerMock.On("VerifyAlreadyInUse").Return(nil)
	controllerMock.On("DeleteAccount").Return(nil)
	controllerMock.On("GetAccountIDByEmail").Return(uuid.New(), nil)
	controllerMock.On("UserIsApplicationAdmin").Return(false, nil)

	_ = controllerMock.CreateAccount(&accountEntities.Account{})
	_, _ = controllerMock.Login(&accountEntities.LoginData{})
	_ = controllerMock.ValidateEmail(uuid.New())
	_ = controllerMock.SendResetPasswordCode("")
	_, _ = controllerMock.VerifyResetPasswordCode(&accountEntities.ResetCodeData{})
	_ = controllerMock.ChangePassword(uuid.New(), "")
	_, _ = controllerMock.RenewToken("", "")
	_ = controllerMock.Logout(uuid.New())
	_, _, _ = controllerMock.createTokenWithAccountPermissions(&accountEntities.Account{})
	_ = controllerMock.VerifyAlreadyInUse(&accountEntities.ValidateUnique{})
	_ = controllerMock.DeleteAccount(uuid.New())
	_, _ = controllerMock.GetAccountIDByEmail(uuid.New().String(), "")
	_, _ = controllerMock.UserIsApplicationAdmin(uuid.New())
}
func TestNewAccountController(t *testing.T) {
	t.Run("should create a new controller", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)
	})
}

func TestCreateAccount(t *testing.T) {
	t.Run("should success create account with no errors", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		mockWrite.On("Create").Return(&response.Response{})
		brokerMock.On("Publish").Return(nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		account := &accountEntities.Account{
			Email:    "test@test.com",
			Password: "test",
			Username: "test",
		}

		err := controller.CreateAccount(account)
		assert.NoError(t, err)
	})

	t.Run("should return error when creating account in database", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp.SetError(errors.New("test")))

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		account := &accountEntities.Account{
			Email:    "test@test.com",
			Password: "test",
			Username: "test",
		}

		err := controller.CreateAccount(account)
		assert.Error(t, err)
	})

	t.Run("should return error when duplicated key in database", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		resp := &response.Response{}
		mockWrite.On("Create").Return(
			resp.SetError(errors.New("pq: duplicate key value violates unique constraint \"accounts_email_key\"")))

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		account := &accountEntities.Account{
			Email:    "test@test.com",
			Password: "test",
			Username: "test",
		}

		err := controller.CreateAccount(account)
		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorEmailAlreadyInUse, err)
	})

	t.Run("should success create account with no errors and no email validation", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		mockWrite.On("Create").Return(&response.Response{})

		_ = os.Setenv("HORUSEC_ACCOUNT_DISABLE_EMAIL_SERVICE", "true")
		appConfig := app.SetupApp()

		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		account := &accountEntities.Account{
			Email:    "test@test.com",
			Password: "test",
			Username: "test",
		}

		err := controller.CreateAccount(account)
		assert.NoError(t, err)
	})
}

func TestLogin(t *testing.T) {
	t.Run("should return no error when everything it is ok", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		account := &accountEntities.Account{
			AccountID:   uuid.New(),
			Email:       "test@test.com",
			Password:    "$2a$10$rkdf/ZuW4Gn1KTDNTRyhdelrwL8GW7mPARwRfLKkCKuq/6vyHu2H.",
			Username:    "test",
			IsConfirmed: true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		resp := &response.Response{}
		mockRead.On("Find").Once().Return(resp.SetData(account))
		cacheRepositoryMock.On("Set").Return(nil)
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{}, nil)

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))
		mockWrite.On("Update").Return(resp)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		loginResponse, err := controller.Login(&accountEntities.LoginData{Email: "test@test.com", Password: "test"})
		assert.NoError(t, err)
		assert.NotEmpty(t, loginResponse)
	})

	t.Run("should return error invalid username or password", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		account := &accountEntities.Account{
			AccountID:   uuid.New(),
			Email:       "test@test.com",
			Password:    "$2a$10$rkdf/ZuW4Gn1KTDNTRyhdelrwL8GW7mPARwRfLKkCKuq/6vyHu2H.",
			Username:    "test",
			IsConfirmed: true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		resp := &response.Response{}
		mockRead.On("Find").Once().Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		loginResponse, err := controller.Login(&accountEntities.LoginData{Email: "test@test.com", Password: "test123"})
		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorWrongEmailOrPassword, err)
		assert.Empty(t, loginResponse)
	})

	t.Run("should return while finding registry in database", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		resp := &response.Response{}
		respWithError := &response.Response{}
		mockRead.On("Find").Once().Return(respWithError.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)

		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		loginResponse, err := controller.Login(&accountEntities.LoginData{Email: "test@test.com", Password: "test123"})
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
		assert.Empty(t, loginResponse)
	})
}

func TestValidateEmail(t *testing.T) {
	t.Run("should return no error when valid data", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		account := &accountEntities.Account{
			IsConfirmed: false,
		}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.ValidateEmail(uuid.New())
		assert.NoError(t, err)
	})

	t.Run("should return error when invalid data", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.ValidateEmail(uuid.New())
		assert.Error(t, err)
		assert.Error(t, errors.New("test"))
	})
}

func TestSendResetPasswordCode(t *testing.T) {
	t.Run("should success send code with no errors", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		account := &accountEntities.Account{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Set").Return(nil)
		brokerMock.On("Publish").Return(nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.SendResetPasswordCode("test@test.com")
		assert.NoError(t, err)
	})

	t.Run("should return error while setting cache", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		account := &accountEntities.Account{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Set").Return(errors.New("test"))

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.SendResetPasswordCode("test@test.com")
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return error while getting sql database account", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.SendResetPasswordCode("test@test.com")
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})
}

func TestVerifyResetPasswordCode(t *testing.T) {
	t.Run("should success verify code and return a new token", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		account := &accountEntities.Account{}
		resp := &response.Response{}

		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("123456")}, nil)
		cacheRepositoryMock.On("Del").Return(nil)
		mockRead.On("Find").Once().Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		data := &accountEntities.ResetCodeData{Email: "test@test.com", Code: "123456"}
		token, err := controller.VerifyResetPasswordCode(data)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("should return when finding email", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		resp := &response.Response{}

		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("123456")}, nil)
		cacheRepositoryMock.On("Del").Return(nil)
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		data := &accountEntities.ResetCodeData{Email: "test@test.com", Code: "123456"}
		_, err := controller.VerifyResetPasswordCode(data)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return when getting cache data", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("")}, errors.New("test"))

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		data := &accountEntities.ResetCodeData{Email: "test@test.com", Code: "123456"}
		_, err := controller.VerifyResetPasswordCode(data)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return no error but code is different", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("654321")}, nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		data := &accountEntities.ResetCodeData{Email: "test@test.com", Code: "123456"}
		_, err := controller.VerifyResetPasswordCode(data)
		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorInvalidResetPasswordCode, err)
	})
}

func TestResetPassword(t *testing.T) {
	t.Run("should success reset password", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		account := &accountEntities.Account{}
		resp := &response.Response{}

		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)
		cacheRepositoryMock.On("Del").Return(nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.ChangePassword(uuid.New(), "123456")
		assert.NoError(t, err)
	})

	t.Run("should return error when finding account", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		resp := &response.Response{}

		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.ChangePassword(uuid.New(), "123456")
		assert.Error(t, err)
	})
}

func TestRenewToken(t *testing.T) {
	account := &accountEntities.Account{
		AccountID: uuid.UUID{},
		Email:     "test@test.com",
		Username:  "test",
	}

	token, _, _ := jwt.CreateToken(account, nil)

	t.Run("should success renew token", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		account := &accountEntities.Account{}
		resp := &response.Response{}

		mockRead.On("Find").Once().Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("test")}, nil)
		cacheRepositoryMock.On("Del").Return(nil)
		cacheRepositoryMock.On("Set").Return(nil)

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		renewResponse, err := controller.RenewToken("test", token)
		assert.NoError(t, err)
		assert.NotEmpty(t, renewResponse)
	})

	t.Run("should return error while refreshing token", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		account := &accountEntities.Account{}
		resp := &response.Response{}

		mockRead.On("Find").Once().Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("test")}, nil)
		cacheRepositoryMock.On("Del").Return(nil)
		cacheRepositoryMock.On("Set").Return(errors.New("test"))

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		renewResponse, err := controller.RenewToken("test", token)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
		assert.Nil(t, renewResponse)
	})

	t.Run("should return error getting account", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		resp := &response.Response{}

		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("test")}, nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		renewResponse, err := controller.RenewToken("test", token)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
		assert.Nil(t, renewResponse)
	})

	t.Run("should return error when token do not match", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		resp := &response.Response{}

		account.AccountID = uuid.New()
		token, _, _ := jwt.CreateToken(account, nil)

		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("test")}, nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		renewResponse, err := controller.RenewToken("testError", token)
		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorNotFoundRefreshTokenInCache, err)
		assert.Nil(t, renewResponse)
	})

	t.Run("should return error invalid signature", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		resp := &response.Response{}

		account.AccountID = uuid.New()
		token, _, _ := jwt.CreateToken(account, nil)

		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("test")}, nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJ1c2VybmFtZSI6In" +
			"Rlc3QiLCJleHAiOjE1OTM1NDAwMjAsImlhdCI6MTU5MzUzNjQyMCwiaXNzIjoiaG9ydXMiLCJzdWIiOiJjMTViNTMwM" +
			"C1hMDgwLTQ5ZTItODRiMy0wZjEyYmIwOTk1OWIifQ.KFB2608D2WEbehG2B80GuaqzSfAKnPEYzMQ4F-ZwR-e"

		renewResponse, err := controller.RenewToken("test", token)
		assert.Error(t, err)
		assert.Equal(t, "signature is invalid", err.Error())
		assert.Nil(t, renewResponse)
	})

	t.Run("should return when empty response from cache", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		resp := &response.Response{}

		account.AccountID = uuid.New()
		token, _, _ := jwt.CreateToken(account, nil)

		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("")}, nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		renewResponse, err := controller.RenewToken("test", token)
		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorNotFoundRefreshTokenInCache, err)
		assert.Nil(t, renewResponse)
	})

	t.Run("should return tokens do not math", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		resp := &response.Response{}

		accountMock := &accountEntities.Account{
			AccountID: uuid.New(),
			Email:     "test@test.com",
			Username:  "test",
		}

		mockRead.On("Find").Return(resp.SetData(accountMock))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("test")}, nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		renewResponse, err := controller.RenewToken("test", token)
		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorAccessAndRefreshTokenNotMatch, err)
		assert.Nil(t, renewResponse)
	})
}

func TestLogout(t *testing.T) {
	t.Run("should success logout", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()
		account := &accountEntities.Account{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)
		cacheRepositoryMock.On("Del").Return(nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.Logout(uuid.New())
		assert.NoError(t, err)
	})

	t.Run("should success logout", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		cacheRepositoryMock.On("Del").Return(nil)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.Logout(uuid.New())
		assert.Error(t, err)
	})
}

func TestCreateTokenWithAccountPermissions(t *testing.T) {
	t.Run("should successfully create a token", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(&[]roles.AccountRepository{}))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		account := &accountEntities.Account{}
		token, _, err := controller.createTokenWithAccountPermissions(account)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

}

func TestVerifyAlreadyInUse(t *testing.T) {
	t.Run("should return no errors when email and username are not in use", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		account := &accountEntities.Account{}

		resp := &response.Response{}
		resp.SetData(account)
		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.VerifyAlreadyInUse(&accountEntities.ValidateUnique{})

		assert.NoError(t, err)
	})

	t.Run("should return error when username already in use", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		account := &accountEntities.Account{Username: "test"}

		resp := &response.Response{}
		resp.SetData(account)
		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.VerifyAlreadyInUse(&accountEntities.ValidateUnique{})

		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorUsernameAlreadyInUse, err)
	})

	t.Run("should return error when email already in use", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		account := &accountEntities.Account{Email: "test"}

		resp := &response.Response{}
		resp.SetData(account)
		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.VerifyAlreadyInUse(&accountEntities.ValidateUnique{})

		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorEmailAlreadyInUse, err)
	})
}

func TestDeleteAccount(t *testing.T) {
	t.Run("should success delete account", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		resp := &response.Response{}
		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Delete").Return(resp)

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.DeleteAccount(uuid.New())

		assert.NoError(t, err)
	})

	t.Run("should return error when getting account", func(t *testing.T) {
		brokerMock := &broker.Mock{}
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}
		useCases := accountUseCases.NewAccountUseCases()

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		appConfig := app.SetupApp()
		controller := NewAccountController(brokerMock, mockRead, mockWrite, cacheRepositoryMock, useCases, appConfig)
		assert.NotNil(t, controller)

		err := controller.DeleteAccount(uuid.New())

		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})
}
