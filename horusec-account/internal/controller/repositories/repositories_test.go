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

package repositories

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	"testing"

	repositoryAccountCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_company"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/account"

	"github.com/ZupIT/horusec/horusec-account/config/app"

	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	errorsEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestMock(t *testing.T) {
	t.Run("Should mock correctly", func(t *testing.T) {
		mock := &Mock{}
		mock.On("Create").Return(&accountEntities.Repository{}, nil)
		mock.On("Update").Return(&accountEntities.Repository{}, nil)
		mock.On("Get").Return(&accountEntities.RepositoryResponse{}, nil)
		mock.On("List").Return(&[]accountEntities.RepositoryResponse{}, nil)
		mock.On("CreateAccountRepository").Return(nil)
		mock.On("UpdateAccountRepository").Return(nil)
		mock.On("InviteUser").Return(nil)
		mock.On("Delete").Return(nil)
		mock.On("GetAllAccountsInRepository").Return(&[]roles.AccountRole{}, nil)
		mock.On("RemoveUser").Return(nil)
		_, _ = mock.Create(uuid.New(), &accountEntities.Repository{})
		_, _ = mock.Update(uuid.New(), &accountEntities.Repository{})
		_, _ = mock.Get(uuid.New(), uuid.New())
		_, _ = mock.List(uuid.New(), uuid.New())
		_ = mock.CreateAccountRepository(&roles.AccountRepository{})
		_ = mock.UpdateAccountRepository(uuid.New(), &roles.AccountRepository{})
		_ = mock.InviteUser(&dto.InviteUser{})
		_ = mock.Delete(uuid.New())
		_, _ = mock.GetAllAccountsInRepository(uuid.New())
		_ = mock.RemoveUser(&dto.RemoveUser{})
	})
}
func TestCreate(t *testing.T) {
	t.Run("should success create repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp)
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(resp)

		respFind := &response.Response{}
		respFind.SetError(errorsEnums.ErrNotFoundRecords)
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		_, err := controller.Create(uuid.New(), &accountEntities.Repository{})
		assert.NoError(t, err)
	})

	t.Run("should return error when creating repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp.SetError(errors.New("test")))
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(resp)

		respFind := &response.Response{}
		respFind.SetError(errors.New("test"))
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		_, err := controller.Create(uuid.New(), &accountEntities.Repository{})
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return error when creating account repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		respWithoutError := &response.Response{}
		respWithError := &response.Response{}
		mockWrite.On("Create").Once().Return(respWithoutError)
		mockWrite.On("Create").Return(respWithError.SetError(errors.New("test")))
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("RollbackTransaction").Return(respWithError)

		respFind := &response.Response{}
		respFind.SetError(errorsEnums.ErrNotFoundRecords)
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		_, err := controller.Create(uuid.New(), &accountEntities.Repository{})
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should set the authz groups with the company authz groups value", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Create").Return(resp)
		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(resp)

		respFindCompany := &response.Response{}
		respFindCompany.SetData(&accountEntities.Company{AuthzAdmin: "admin", AuthzMember: "member"})
		mockRead.On("Find").Once().Return(respFindCompany)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		respFind := &response.Response{}
		respFind.SetError(errorsEnums.ErrNotFoundRecords)
		mockRead.On("Find").Return(respFind)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		createdRepo, err := controller.Create(uuid.New(), &accountEntities.Repository{
			AuthzAdmin:      "",
			AuthzMember:     "",
			AuthzSupervisor: "",
		})
		assert.NoError(t, err)
		assert.Equal(t, createdRepo.AuthzAdmin, "admin")
		assert.Equal(t, createdRepo.AuthzMember, "member")
		assert.Equal(t, createdRepo.AuthzSupervisor, "admin")
	})
}

func TestUpdate(t *testing.T) {
	t.Run("should success update repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Return(resp.SetData(&accountEntities.Repository{}))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		_, err := controller.Update(uuid.New(), &accountEntities.Repository{})
		assert.NoError(t, err)
	})

	t.Run("should return error when something went wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockWrite.On("Update").Return(resp)
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		_, err := controller.Update(uuid.New(), &accountEntities.Repository{})
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})
}

func TestGet(t *testing.T) {
	t.Run("should success get repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(&accountEntities.Repository{RepositoryID: uuid.New()}))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		result, err := controller.Get(uuid.New(), uuid.New())
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("should return error when something went wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		_, err := controller.Get(uuid.New(), uuid.New())
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return error when getting repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		respWithError := &response.Response{}
		mockRead.On("Find").Once().Return(resp)
		mockRead.On("Find").Return(respWithError.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		_, err := controller.Get(uuid.New(), uuid.New())
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})
}

func TestUpdateAccountRepository(t *testing.T) {
	t.Run("should success update account repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		accountRepository := &roles.AccountRepository{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp.SetData(accountRepository))

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.UpdateAccountRepository(uuid.UUID{}, accountRepository)
		assert.NoError(t, err)
	})

	t.Run("should return error when user not member of company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		accountRepository := &roles.AccountRepository{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp.SetError(errors.New("test")))

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.UpdateAccountRepository(uuid.UUID{}, accountRepository)
		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorUserNotMemberOfCompany, err)
	})
}

func TestCreateAccountRepository(t *testing.T) {
	t.Run("should success create account repository", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		accountRepository := &roles.AccountRepository{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp)
		mockWrite.On("Create").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.CreateAccountRepository(accountRepository)
		assert.NoError(t, err)
	})

	t.Run("should return error when user not member of company", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		accountRepository := &roles.AccountRepository{}
		brokerMock := &broker.Mock{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.CreateAccountRepository(accountRepository)
		assert.Error(t, err)
		assert.Equal(t, errorsEnums.ErrorUserNotMemberOfCompany, err)
	})
}

func TestList(t *testing.T) {
	t.Run("should successfully retrieve repositories list with user member", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, nil, &roles.AccountCompany{Role: account.Member}))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		brokerMock := &broker.Mock{}
		repositoryMock := &repositoryRepo.Mock{}
		repositoryMock.On("List").Return(&[]accountEntities.RepositoryResponse{{}}, nil)

		controller := &Controller{
			databaseWrite:            mockWrite,
			databaseRead:             mockRead,
			repository:               repositoryMock,
			accountRepositoryRepo:    nil,
			accountRepository:        nil,
			accountCompanyRepository: repositoryAccountCompany.NewAccountCompanyRepository(mockRead, mockWrite),
			broker:                   brokerMock,
			appConfig:                &app.Config{},
			repositoriesUseCases:     nil,
		}

		repositories, err := controller.List(uuid.New(), uuid.New())
		assert.NoError(t, err)
		assert.NotNil(t, repositories)
	})
	t.Run("should return error in repositories list", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		mockRead.On("Find").Return(response.NewResponse(0, nil, &roles.AccountCompany{Role: account.Member}))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		brokerMock := &broker.Mock{}
		repositoryMock := &repositoryRepo.Mock{}
		repositoryMock.On("List").Return(&[]accountEntities.RepositoryResponse{{}}, errors.New("unexpected error"))

		controller := &Controller{
			databaseWrite:            mockWrite,
			databaseRead:             mockRead,
			repository:               repositoryMock,
			accountRepositoryRepo:    nil,
			accountRepository:        nil,
			accountCompanyRepository: repositoryAccountCompany.NewAccountCompanyRepository(mockRead, mockWrite),
			broker:                   brokerMock,
			appConfig:                &app.Config{},
			repositoriesUseCases:     nil,
		}

		_, err := controller.List(uuid.New(), uuid.New())
		assert.Error(t, err)
	})
}

func TestInviteUser(t *testing.T) {
	inviteUser := &dto.InviteUser{
		Role:  "admin",
		Email: "test@test.com",
	}

	repository := &accountEntities.Repository{
		CompanyID:    uuid.New(),
		RepositoryID: uuid.New(),
		Name:         "test",
	}

	account := &authEntities.Account{
		AccountID: uuid.New(),
		Email:     "test@test.com",
		Username:  "test",
	}

	t.Run("should successfully invite user", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		respRepository := &response.Response{}
		respAccount := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetData(account))
		mockRead.On("Find").Return(respRepository.SetData(repository))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Create").Return(respRepository)
		brokerMock.On("Publish").Return(nil)

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.InviteUser(inviteUser)
		assert.NoError(t, err)
	})

	t.Run("should return error creating account repository", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		respRepository := &response.Response{}
		respAccount := &response.Response{}
		respWithError := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetData(account))
		mockRead.On("Find").Return(respRepository.SetData(repository))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Create").Return(respWithError.SetError(errors.New("test")))

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.InviteUser(inviteUser)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return error getting repository", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		respRepository := &response.Response{}
		respAccount := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetData(account))
		mockRead.On("Find").Return(respRepository.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.InviteUser(inviteUser)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should return error getting account", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		respAccount := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{})

		err := controller.InviteUser(inviteUser)
		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
	})

	t.Run("should successfully invite user without email", func(t *testing.T) {
		mockWrite := &relational.MockWrite{}
		mockRead := &relational.MockRead{}
		brokerMock := &broker.Mock{}

		respRepository := &response.Response{}
		respAccount := &response.Response{}
		mockRead.On("Find").Once().Return(respAccount.SetData(account))
		mockRead.On("Find").Return(respRepository.SetData(repository))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Create").Return(respRepository)

		controller := NewController(mockWrite, mockRead, brokerMock, &app.Config{DisabledBroker: true})

		err := controller.InviteUser(inviteUser)
		assert.NoError(t, err)
	})
}

func TestDeleteRepository(t *testing.T) {
	t.Run("should successfully delete repository", func(t *testing.T) {
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

	t.Run("should successfully remove user from repository", func(t *testing.T) {
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

	t.Run("should return error when getting account", func(t *testing.T) {
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
