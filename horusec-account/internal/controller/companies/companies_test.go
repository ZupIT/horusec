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

package companies

import (
	"errors"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	companyRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestMock(t *testing.T) {
	t.Run("Should mock correctly", func(t *testing.T) {
		mock := &Mock{}
		mock.On("Create").Return(&accountEntities.Company{}, nil)
		mock.On("Update").Return(&accountEntities.Company{}, nil)
		mock.On("Get").Return(&accountEntities.CompanyResponse{}, nil)
		mock.On("List").Return(&[]accountEntities.CompanyResponse{}, nil)
		mock.On("UpdateAccountCompany").Return(nil)
		mock.On("InviteUser").Return(nil)
		mock.On("Delete").Return(nil)
		mock.On("GetAllAccountsInCompany").Return(&[]roles.AccountRole{}, nil)
		mock.On("RemoveUser").Return(nil)
		_, _ = mock.Create(uuid.New(), &accountEntities.Company{}, []string{})
		_, _ = mock.Update(uuid.New(), &accountEntities.Company{}, []string{})
		_, _ = mock.Get(uuid.New(), uuid.New())
		_, _ = mock.List(uuid.New(), []string{})
		_ = mock.UpdateAccountCompany(&roles.AccountCompany{})
		_ = mock.InviteUser(&dto.InviteUser{})
		_ = mock.Delete(uuid.New())
		_, _ = mock.GetAllAccountsInCompany(uuid.New())
		_ = mock.RemoveUser(&dto.RemoveUser{})
	})
}

func TestNewCompaniesController(t *testing.T) {
	t.Run("should create a new controller", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})
		assert.NotNil(t, controller)
	})
}

func TestCreateCompany(t *testing.T) {
	t.Run("should successfully create company without errors", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockTx := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		company := &accountEntities.Company{
			Name: "test",
		}

		r := &response.Response{}
		r.SetData(company)
		mockTx.On("Create").Return(r)
		mockTx.On("CommitTransaction").Return(&response.Response{})

		mockWrite.On("StartTransaction").Return(mockTx)

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})
		newCompany, err := controller.Create(uuid.New(), company, []string{})
		assert.NoError(t, err)
		assert.NotNil(t, newCompany)
		mockTx.AssertCalled(t, "CommitTransaction")
		mockTx.AssertNumberOfCalls(t, "Create", 2)
	})

	t.Run("should return error when creating company with invalid ldap groups", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockTx := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		company := &accountEntities.Company{
			Name: "test",
		}

		r := &response.Response{}
		r.SetData(company)
		mockTx.On("Create").Return(r)
		mockTx.On("CommitTransaction").Return(&response.Response{})

		mockWrite.On("StartTransaction").Return(mockTx)

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{
			ConfigAuth: authEntities.ConfigAuth{AuthType: authEnums.Ldap},
		})

		_, err := controller.Create(uuid.New(), company, []string{})
		assert.Error(t, err)
	})

	t.Run("should fails to create a company and rollback the transaction", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockTx := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		company := &accountEntities.Company{
			Name: "test",
		}

		r := &response.Response{}
		r.SetData(company)
		mockTx.On("Create").Once().Return(r)

		re := &response.Response{}
		re.SetError(errors.New("test"))
		mockTx.On("Create").Return(re)

		mockTx.On("RollbackTransaction").Return(re)

		mockWrite.On("StartTransaction").Return(mockTx)

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})
		newCompany, err := controller.Create(uuid.New(), company, []string{})

		assert.Error(t, err, "test")
		assert.Nil(t, newCompany)
		mockTx.AssertCalled(t, "RollbackTransaction")
		mockTx.AssertNumberOfCalls(t, "Create", 2)
	})

	t.Run("should fails to create a company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockTx := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		r := &response.Response{}
		r.SetError(errors.New("test"))
		mockTx.On("Create").Return(r)
		mockWrite.On("StartTransaction").Return(mockTx)

		company := &accountEntities.Company{
			Name: "test",
		}
		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})
		newCompany, err := controller.Create(uuid.New(), company, []string{})

		assert.Error(t, err, "test")
		assert.Nil(t, newCompany)
		mockTx.AssertNotCalled(t, "RollbackTransaction")
		mockTx.AssertNotCalled(t, "RollbackTransaction")
		mockTx.AssertNumberOfCalls(t, "Create", 1)
	})
}

func TestUpdateCompany(t *testing.T) {
	t.Run("should successfully update company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		company := &accountEntities.Company{
			Name: "test",
		}
		r := &response.Response{}
		r.SetData(company)
		mockWrite.On("Update").Return(r)

		updatedCompany, err := controller.Update(uuid.New(), company, []string{})

		assert.NotNil(t, updatedCompany)
		assert.NoError(t, err)
	})

	t.Run("should return error when updating company with invalid ldap groups", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{
			ConfigAuth: authEntities.ConfigAuth{AuthType: authEnums.Ldap},
		})

		company := &accountEntities.Company{
			Name: "test",
		}
		r := &response.Response{}
		r.SetData(company)
		mockWrite.On("Update").Return(r)

		_, err := controller.Update(uuid.New(), company, []string{})

		assert.Error(t, err)
	})
}

func TestGetCompany(t *testing.T) {
	t.Run("should successfully get company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		company := &accountEntities.Company{
			Name: "test",
		}
		r := &response.Response{}
		r.SetData(company)
		mockRead.On("Find").Return(r)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		updatedCompany, err := controller.Get(uuid.New(), uuid.New())

		assert.NotNil(t, updatedCompany)
		assert.NoError(t, err)
	})

	t.Run("should return error getting company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		company := &accountEntities.Company{
			Name: "test",
		}

		r := &response.Response{}
		rWithError := &response.Response{}

		r.SetData(company)
		mockRead.On("Find").Once().Return(r)
		mockRead.On("Find").Return(rWithError.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		_, err := controller.Get(uuid.New(), uuid.New())

		assert.Error(t, err)
		assert.Error(t, errors.New("test"), err)
	})

	t.Run("should return error while get account company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		r := &response.Response{}
		r.SetError(errors.New("test"))

		mockRead.On("Find").Return(r)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		updatedCompany, err := controller.Get(uuid.New(), uuid.New())

		assert.Nil(t, updatedCompany)
		assert.Error(t, err)
	})
}

func TestUpdateAccountCompany(t *testing.T) {
	t.Run("should successfully update account company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		accountCompany := &roles.AccountCompany{
			Role:      "admin",
			AccountID: uuid.New(),
		}
		r := &response.Response{}
		r.SetData(accountCompany)
		mockWrite.On("Update").Return(r)
		mockRead.On("Find").Return(r)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		err := controller.UpdateAccountCompany(accountCompany)

		assert.NoError(t, err)
	})
}

func TestList(t *testing.T) {
	t.Run("should successfully retrieve companies list", func(t *testing.T) {
		companyRepoMock := &companyRepo.Mock{}

		companyResponse := &[]accountEntities.CompanyResponse{
			{
				CompanyID:   uuid.New(),
				Name:        "",
				Role:        "",
				Description: "",
				CreatedAt:   time.Time{},
				UpdatedAt:   time.Time{},
			},
		}

		companyRepoMock.On("GetAllOfAccount").Return(companyResponse, nil)

		controller := Controller{
			repoCompany: companyRepoMock,
			appConfig:   &app.Config{},
		}

		repositories, err := controller.List(uuid.New(), []string{})
		assert.NoError(t, err)
		assert.NotNil(t, repositories)
	})

	t.Run("should successfully retrieve companies list with ldap", func(t *testing.T) {
		companyRepoMock := &companyRepo.Mock{}

		companyResponse := &[]accountEntities.CompanyResponse{
			{
				CompanyID:   uuid.New(),
				Name:        "",
				Role:        "",
				Description: "",
				CreatedAt:   time.Time{},
				UpdatedAt:   time.Time{},
			},
		}

		companyRepoMock.On("ListByLdapPermissions").Return(companyResponse, nil)

		appConfig := &app.Config{ConfigAuth: authEntities.ConfigAuth{AuthType: authEnums.Ldap}}

		controller := Controller{
			repoCompany: companyRepoMock,
			appConfig:   appConfig,
		}

		repositories, err := controller.List(uuid.New(), []string{})
		assert.NoError(t, err)
		assert.NotNil(t, repositories)
	})
}

func TestInviteUser(t *testing.T) {
	inviteUser := &dto.InviteUser{
		Role:  "admin",
		Email: "test@test.com",
	}

	company := &accountEntities.Company{
		CompanyID: uuid.New(),
		Name:      "test",
	}

	account := &authEntities.Account{
		AccountID: uuid.New(),
		Email:     "test@test.com",
		Username:  "test",
	}

	t.Run("should success invite user", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		respCompany := &response.Response{}
		respAccount := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetData(account))
		mockRead.On("Find").Return(respCompany.SetData(company))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		brokerMock.On("Publish").Return(nil)
		mockWrite.On("Create").Return(respCompany)

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.InviteUser(inviteUser)
		assert.NoError(t, err)
	})

	t.Run("should return error when creating account company", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		respCompany := &response.Response{}
		respAccount := &response.Response{}
		respWithError := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetData(account))
		mockRead.On("Find").Return(respCompany.SetData(company))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Create").Return(respWithError.SetError(errors.New("test")))

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.InviteUser(inviteUser)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return error while getting company", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		respCompany := &response.Response{}
		respAccount := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetData(account))
		mockRead.On("Find").Return(respCompany.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.InviteUser(inviteUser)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return error while getting account", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		respAccount := &response.Response{}
		mockRead.On("Find").Return(respAccount.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.InviteUser(inviteUser)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should success invite user without email", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		respCompany := &response.Response{}
		respAccount := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetData(account))
		mockRead.On("Find").Return(respCompany.SetData(company))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Create").Return(respCompany)

		appConfig := &app.Config{ConfigAuth: authEntities.ConfigAuth{DisabledBroker: true}}
		controller := NewController(mockWrite, mockRead, brokerMock, appConfig)

		err := controller.InviteUser(inviteUser)
		assert.NoError(t, err)
	})
}

func TestDeleteCompany(t *testing.T) {
	t.Run("should successfully delete company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)

		err := controller.Delete(uuid.New())
		assert.NoError(t, err)
	})
}

func TestRemoveUser(t *testing.T) {
	account := authEntities.Account{}

	t.Run("should successfully remove user from company and repositories", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		resp := &response.Response{}
		mockWrite.On("Delete").Return(resp)
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		err := controller.RemoveUser(&dto.RemoveUser{})
		assert.NoError(t, err)
	})

	t.Run("should return error when something went wrong while deleting account company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		resp := &response.Response{}
		respWithError := &response.Response{}
		mockWrite.On("Delete").Once().Return(resp)
		mockWrite.On("Delete").Return(respWithError.SetError(errors.New("test")))
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		err := controller.RemoveUser(&dto.RemoveUser{})
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return error when something went wrong while removing user from all repositories", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		resp := &response.Response{}
		respWithError := &response.Response{}
		mockWrite.On("Delete").Return(respWithError.SetError(errors.New("test")))
		mockRead.On("Find").Return(resp.SetData(account))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		err := controller.RemoveUser(&dto.RemoveUser{})
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return error when something went wrong while getting account", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		err := controller.RemoveUser(&dto.RemoveUser{})
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})
}

func TestGetAllAccountsInCompany(t *testing.T) {
	t.Run("should successfully get roles", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}
		roleSlice := []roles.AccountRole{
			{
				Email: "test",
			},
			{
				Email: "test",
			},
		}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		resp := &response.Response{}
		mockRead.On("RawSQL").Return(resp.SetData(roleSlice))

		result, err := controller.GetAllAccountsInCompany(uuid.New())
		assert.NoError(t, err)
		assert.NotEmpty(t, result, 2)
	})
}

func TestGetAccountIDByEmail(t *testing.T) {
	t.Run("should successfully get account id by email", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		account := &authEntities.Account{
			AccountID: uuid.UUID{},
		}

		resp := &response.Response{}
		resp.SetData(account)

		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		accountID, err := controller.GetAccountIDByEmail("")

		assert.NotNil(t, accountID)
		assert.NoError(t, err)
	})

	t.Run("should return error while getting account id by email", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		resp := &response.Response{}
		resp.SetError(errors.New("test"))

		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		accountID, err := controller.GetAccountIDByEmail("")

		assert.Equal(t, uuid.Nil, accountID)
		assert.Error(t, err)
	})
}
