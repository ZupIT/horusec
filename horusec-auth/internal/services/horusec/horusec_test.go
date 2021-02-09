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

package horusec

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccount "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	repositoryAccountCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_company"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	entityCache "github.com/ZupIT/horusec/development-kit/pkg/entities/cache"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	authUseCases "github.com/ZupIT/horusec/horusec-auth/internal/usecases/auth"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func generateToken() string {
	token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(&authEntities.Account{
		AccountID: uuid.New(),
		Email:     "test@test.com",
		Password:  "test",
		Username:  "test",
	}, nil)

	return token
}

func TestNewHorusAuthService(t *testing.T) {
	t.Run("should success create new service", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		service := NewHorusAuthService(mockRead, mockWrite)

		assert.NotNil(t, service)
	})
}

func TestAuthenticate(t *testing.T) {
	t.Run("should success authenticate login", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &authEntities.Account{
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

		service := Service{
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, mockWrite),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, mockWrite),
			accountRepository:     repositoryAccount.NewAccountRepository(mockRead, mockWrite),
			accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
			cacheRepository:       cacheRepositoryMock,
			authUseCases:          authUseCases.NewAuthUseCases(),
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
		}

		credentials := &dto.Credentials{
			Username: "test@test.com",
			Password: "test",
		}

		result, err := service.Authenticate(credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("should return error invalid username or password", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &authEntities.Account{
			AccountID:   uuid.New(),
			Email:       "test@test.com",
			Password:    "$2a$10$rkdf/ZuW4Gn1KTDNTRyhdelrwL8GW7mPARwHfLKkCKuq/6vyHu2H.",
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

		service := Service{
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, mockWrite),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, mockWrite),
			accountRepository:     repositoryAccount.NewAccountRepository(mockRead, mockWrite),
			accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
			cacheRepository:       cacheRepositoryMock,
			authUseCases:          authUseCases.NewAuthUseCases(),
		}

		credentials := &dto.Credentials{
			Username: "test@test.com",
			Password: "test",
		}

		result, err := service.Authenticate(credentials)

		assert.Error(t, err)
		assert.Equal(t, errorsEnum.ErrorWrongEmailOrPassword, err)
		assert.Empty(t, result)
	})

	t.Run("should return while finding registry in database", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		resp := &response.Response{}
		respWithError := &response.Response{}
		mockRead.On("Find").Once().Return(respWithError.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)

		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))

		service := Service{
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, mockWrite),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, mockWrite),
			accountRepository:     repositoryAccount.NewAccountRepository(mockRead, mockWrite),
			accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
			cacheRepository:       cacheRepositoryMock,
		}

		credentials := &dto.Credentials{
			Username: "test@test.com",
			Password: "test",
		}

		result, err := service.Authenticate(credentials)

		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
		assert.Empty(t, result)
	})

	t.Run("should return error while setting data in cache", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		cacheRepositoryMock := &cache.Mock{}

		account := &authEntities.Account{
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
		cacheRepositoryMock.On("Set").Return(errors.New("test"))
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockWrite.On("Update").Return(resp)
		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{}, nil)

		resp2 := &response.Response{}
		mockRead.On("Find").Return(resp2.SetData(nil))
		mockWrite.On("Update").Return(resp)

		service := Service{
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, mockWrite),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, mockWrite),
			accountRepository:     repositoryAccount.NewAccountRepository(mockRead, mockWrite),
			accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
			cacheRepository:       cacheRepositoryMock,
			authUseCases:          authUseCases.NewAuthUseCases(),
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
		}

		credentials := &dto.Credentials{
			Username: "test@test.com",
			Password: "test",
		}

		result, err := service.Authenticate(credentials)

		assert.Error(t, err)
		assert.Equal(t, errors.New("test"), err)
		assert.Empty(t, result)
	})
}

func TestIsAuthorizedCompanyMember(t *testing.T) {
	t.Run("should success authenticate with company member", func(t *testing.T) {
		mockRead := &relational.MockRead{}

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Member,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5NzNmNDg1Yy0xMmNiLTExZWItYWRjMS0wMjQyYWMxM" +
				"jAwMDIiLCJuYW1lIjoiSm9obiBEb2UiLJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidGVzdCIsImVtYWlsIjoidGVzdEB0Z" +
				"XN0LmNvbSJ9.fsqlUToV55E1s-ll4Db8AZgPbf3QF_IvIojun1QNECo",
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

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Member,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Supervisor,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5NzNmNDg1Yy0xMmNiLTExZWItYWRjMS0wMjQyYWMxM" +
				"jAwMDIiLCJuYW1lIjoiSm9obiBEb2UiLJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidGVzdCIsImVtYWlsIjoidGVzdEB0Z" +
				"XN0LmNvbSJ9.fsqlUToV55E1s-ll4Db8AZgPbf3QF_IvIojun1QNECo",
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

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Member,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Supervisor,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5NzNmNDg1Yy0xMmNiLTExZWItYWRjMS0wMjQyYWMx" +
				"MjAwMDIiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidGVzdCIsImVtYWlsIjoidGVzdEB" +
				"0ZXN0LmNvbSJ9.fsqlUToV55E1s-ll4Db8AZgPbf3QF_IvIojun1QNEo",
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

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Admin,
		}

		respRepository := response.Response{}
		respCompany := response.Response{}
		mockRead.On("Find").Once().Return(respRepository.SetError(errors.New("test")))
		mockRead.On("Find").Return(respCompany.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Supervisor,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Admin,
		}

		respRepository := response.Response{}
		respCompany := response.Response{}
		mockRead.On("Find").Once().Return(respRepository.SetError(errors.New("test")))
		mockRead.On("Find").Return(respCompany.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Member,
		}

		respRepository := response.Response{}
		respCompany := response.Response{}
		mockRead.On("Find").Once().Return(respRepository.SetError(errors.New("test")))
		mockRead.On("Find").Return(respCompany.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5NzNmNDg1Yy0xMmNiLTExZWItYWRjMS0wMjQyYWMx" +
				"MjAwMDIiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidGVzdCIsImVtYWlsIjoidGVzdEB" +
				"0ZXN0LmNvbSJ9.fsqlUToV55E1s-ll4Db8AZgPbf3QF_IvIojun1QNEo",
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

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Admin,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Admin,
		}

		respRepository := response.Response{}
		respCompany := response.Response{}
		mockRead.On("Find").Once().Return(respRepository.SetError(errors.New("test")))
		mockRead.On("Find").Return(respCompany.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Supervisor,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		accountRepository := &roles.AccountRepository{
			Role: accountEnums.Member,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
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

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5NzNmNDg1Yy0xMmNiLTExZWItYWRjMS0wMjQyYWMx" +
				"MjAwMDIiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidGVzdCIsImVtYWlsIjoidGVzdEB" +
				"0ZXN0LmNvbSJ9.fsqlUToV55E1s-ll4Db8AZgPbf3QF_IvIojun1QNEo",
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

		accountCompany := &roles.AccountCompany{
			Role: accountEnums.Member,
		}

		respRepository := response.Response{}
		respCompany := response.Response{}
		mockRead.On("Find").Once().Return(respRepository.SetError(errors.New("test")))
		mockRead.On("Find").Return(respCompany.SetData(accountCompany))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:                   jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			repoAccountCompany:    repositoryAccountCompany.NewAccountCompanyRepository(mockRead, nil),
			repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(mockRead, nil),
			repositoryRepo:        repositoryRepo.NewRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})
}

func TestIsApplicationAdmin(t *testing.T) {
	t.Run("should success authenticate with application admin", func(t *testing.T) {
		mockRead := &relational.MockRead{}

		accountRepository := &authEntities.Account{
			IsApplicationAdmin: true,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:               jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			accountRepository: repositoryAccount.NewAccountRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
			Role:         authEnums.ApplicationAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.NoError(t, err)
		assert.True(t, result)
	})
	t.Run("should error when authenticate with wrong token", func(t *testing.T) {
		mockRead := &relational.MockRead{}

		accountRepository := &authEntities.Account{
			IsApplicationAdmin: true,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:               jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			accountRepository: repositoryAccount.NewAccountRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        "WRONG TOKEN",
			Role:         authEnums.ApplicationAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})
	t.Run("should error when get user in database authenticate", func(t *testing.T) {
		mockRead := &relational.MockRead{}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetError(errors.New("not found content")))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:               jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			accountRepository: repositoryAccount.NewAccountRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
			Role:         authEnums.ApplicationAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})
	t.Run("should success but user is not application admin when get user in database", func(t *testing.T) {
		mockRead := &relational.MockRead{}

		accountRepository := &authEntities.Account{
			IsApplicationAdmin: false,
		}

		resp := response.Response{}
		mockRead.On("Find").Return(resp.SetData(accountRepository))
		mockRead.On("SetFilter").Return(&gorm.DB{})

		service := Service{
			jwt:               jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)),
			accountRepository: repositoryAccount.NewAccountRepository(mockRead, nil),
		}

		authorizationData := &dto.AuthorizationData{
			Token:        generateToken(),
			Role:         authEnums.ApplicationAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := service.IsAuthorized(authorizationData)

		assert.Error(t, err)
		assert.False(t, result)
	})
}
