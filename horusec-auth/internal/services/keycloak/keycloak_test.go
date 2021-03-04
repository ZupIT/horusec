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

package keycloak

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	"testing"

	"github.com/Nerzal/gocloak/v7"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccountCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_company"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	keycloakService "github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestNewKeycloakAuthService(t *testing.T) {
	mockRead := &relational.MockRead{}
	service := NewKeycloakAuthService(mockRead)
	assert.NotEmpty(t, service)
}

func TestService_Authenticate(t *testing.T) {
	t.Run("Should run authentication without error", func(t *testing.T) {
		mock := &keycloakService.Mock{}

		mock.On("LoginOtp").Return(&gocloak.JWT{
			AccessToken:      "access_token",
			IDToken:          uuid.New().String(),
			ExpiresIn:        15,
			RefreshExpiresIn: 15,
			RefreshToken:     "refresh_token",
			TokenType:        "unique",
		}, nil)

		service := &Service{keycloak: mock}

		content, err := service.Authenticate(&dto.Credentials{
			Username: "admin",
			Password: "admin",
		})

		assert.NoError(t, err)
		assert.NotEmpty(t, content)
	})
}

func TestIsAuthorizedCompanyMember(t *testing.T) {
	t.Run("should success authenticate with company member", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Member,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.CompanyMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should success authenticate with company admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.CompanyMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should return error when something went wrong while getting role", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.CompanyMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should return error when invalid token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.Nil, errors.New("test"))

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.CompanyMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})
}

func TestIsAuthorizedCompanyAdmin(t *testing.T) {
	t.Run("should success authenticate with company admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.CompanyAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should return error when member", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Member,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.CompanyAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should return error when supervisor", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Supervisor,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.CompanyAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should return error when invalid jwt token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.Nil, errors.New("test"))

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.CompanyAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})
}

func TestIsAuthorizedRepositoryMember(t *testing.T) {
	t.Run("should success authenticate with repository member", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Member,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should success authenticate with repository supervisor", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Supervisor,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should success authenticate with repository admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should return error when something went wrong while getting role", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should return error when invalid token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.Nil, errors.New("test"))

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should success authenticate with company admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Admin,
		}

		respRepository := response.Response{}
		respCompany := response.Response{}
		mockRead.On("Find").Once().Return(respRepository.SetError(errors.New("test")))
		mockRead.On("Find").Return(respCompany.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})
}

func TestIsAuthorizedRepositorySupervisor(t *testing.T) {
	t.Run("should success authenticate with repository supervisor", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Supervisor,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositorySupervisor,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should success authenticate with repository admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token: "test",

			Role:         authEnums.RepositorySupervisor,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should success authenticate with company admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Admin,
		}

		respRepository := response.Response{}
		respCompany := response.Response{}
		mockRead.On("Find").Once().Return(respRepository.SetError(errors.New("test")))
		mockRead.On("Find").Return(respCompany.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositorySupervisor,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should return error when not in repository and company member", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Member,
		}

		respRepository := response.Response{}
		respCompany := response.Response{}
		mockRead.On("Find").Once().Return(respRepository.SetError(errors.New("test")))
		mockRead.On("Find").Return(respCompany.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositorySupervisor,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should return error when something went wrong while getting role", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositorySupervisor,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should return error when invalid token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.Nil, errors.New("test"))

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositorySupervisor,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})
}

func TestIsAuthorizedRepositoryAdmin(t *testing.T) {
	t.Run("should success authenticate with repository admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should success authenticate with company admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Admin,
		}

		respRepository := response.Response{}
		respCompany := response.Response{}
		mockRead.On("Find").Once().Return(respRepository.SetError(errors.New("test")))
		mockRead.On("Find").Return(respCompany.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("should return error when repository supervisor", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Supervisor,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should return error when repository member", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Member,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should return error when something went wrong while getting role", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should return error when invalid token", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.Nil, errors.New("test"))

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})

	t.Run("should return error when not in repository and company member", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(true, nil)
		keycloakMock.On("GetAccountIDByJWTToken").Return(uuid.New(), nil)

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Member,
		}

		respRepository := response.Response{}
		respCompany := response.Response{}
		mockRead.On("Find").Once().Return(respRepository.SetError(errors.New("test")))
		mockRead.On("Find").Return(respCompany.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})
}

func TestIsAuthorized(t *testing.T) {
	t.Run("should success authenticate with repository admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		keycloakMock := &keycloakService.Mock{}

		keycloakMock.On("IsActiveToken").Return(false, errors.New("test"))

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			keycloak:              keycloakMock,
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "test",
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})
}
