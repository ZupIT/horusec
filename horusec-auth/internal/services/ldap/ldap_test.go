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

package ldap

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	companyrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	repositoryrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	ldapservice "github.com/ZupIT/horusec/development-kit/pkg/services/ldap"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewService(t *testing.T) {
	t.Run("should creates a new service instance", func(t *testing.T) {
		dbRead := &relational.MockRead{}
		dbWrite := &relational.MockWrite{}

		ldapService := NewService(dbRead, dbWrite)
		assert.NotNil(t, ldapService)
	})
}

func TestAuthenticate(t *testing.T) {
	t.Run("should return ldap auth response when authenticate is successfully and user exists", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		user := map[string]string{"username": "test", "email": "test@test.com"}
		ldapClientServiceMock.On("Authenticate").Return(true, user, nil)

		resp := response.Response{}
		databaseRead.On("Find").Return(resp.SetData(user))
		databaseRead.On("SetFilter").Return(&gorm.DB{})
		databaseRead.On("Find").Return()

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		credentials := auth.Credentials{}
		result, err := ldapService.Authenticate(&credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("should return ldap auth response when authenticate is successfully and user doesnt exist", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		user := map[string]string{"givenName": "test", "mail": "test@test.com"}
		ldapClientServiceMock.On("Authenticate").Return(true, user, nil)

		respFind := response.Response{}
		respCreate := response.Response{}
		databaseRead.On("Find").Return(respFind.SetError(errors.New("")))
		databaseRead.On("SetFilter").Return(&gorm.DB{})
		databaseRead.On("Find").Return()
		databaseWrite.On("Create").Return(respCreate.SetData(user))

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		credentials := auth.Credentials{}
		result, err := ldapService.Authenticate(&credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("should return  error while creating new account by ldap response", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		user := map[string]string{"username": "test", "email": "test@test.com"}
		ldapClientServiceMock.On("Authenticate").Return(true, user, nil)

		respFind := response.Response{}
		respCreate := response.Response{}
		databaseRead.On("Find").Return(respFind.SetError(errors.New("")))
		databaseRead.On("SetFilter").Return(&gorm.DB{})
		databaseRead.On("Find").Return()
		databaseWrite.On("Create").Return(respCreate.SetError(errors.New("test")))

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		credentials := auth.Credentials{}
		result, err := ldapService.Authenticate(&credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("should return return error when failed to authenticate", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("Authenticate").Return(false, map[string]string{}, nil)

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		credentials := auth.Credentials{}
		result, err := ldapService.Authenticate(&credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("should return return error when failed to authenticate", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("Authenticate").Return(true, map[string]string{}, errors.New("test"))

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		credentials := auth.Credentials{}
		result, err := ldapService.Authenticate(&credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestIsAuthorized(t *testing.T) {
	account := &accountEntities.Account{
		AccountID: uuid.New(),
		Email:     "test@test.com",
		Username:  "test",
	}

	t.Run("should return true and no error when successfully authenticate with company admin", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"admin"}, nil)

		resp := response.Response{}
		company := &accountEntities.Company{
			CompanyID:  uuid.New(),
			AuthzAdmin: "admin",
		}

		databaseRead.On("Find").Return(resp.SetData(company))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.CompanyAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.True(t, result)
		assert.NoError(t, err)
	})

	t.Run("should return false and error when invalid ldap group with company admin", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"test"}, nil)

		resp := response.Response{}
		company := &accountEntities.Company{
			CompanyID:  uuid.New(),
			AuthzAdmin: "admin",
		}

		databaseRead.On("Find").Return(resp.SetData(company))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.CompanyAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.False(t, result)
		assert.Error(t, err)
	})

	t.Run("should return true and no error when successfully authenticate with company member", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"developer"}, nil)

		resp := response.Response{}
		company := &accountEntities.Company{
			CompanyID:   uuid.New(),
			AuthzMember: "developer",
		}

		databaseRead.On("Find").Return(resp.SetData(company))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.CompanyMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.True(t, result)
		assert.NoError(t, err)
	})

	t.Run("should return false and error when invalid ldap group with company member", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"test"}, nil)

		resp := response.Response{}
		company := &accountEntities.Company{
			CompanyID:  uuid.New(),
			AuthzAdmin: "developer",
		}

		databaseRead.On("Find").Return(resp.SetData(company))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.CompanyMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.False(t, result)
		assert.Error(t, err)
	})

	t.Run("should return true and no error when successfully authenticate with repository member", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"developer"}, nil)

		resp := response.Response{}
		repository := &accountEntities.Repository{
			RepositoryID: uuid.New(),
			AuthzMember:  "developer",
		}

		databaseRead.On("Find").Return(resp.SetData(repository))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.RepositoryMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.True(t, result)
		assert.NoError(t, err)
	})

	t.Run("should return false and error when invalid ldap group with repository member", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"test"}, nil)

		resp := response.Response{}
		repository := &accountEntities.Repository{
			RepositoryID: uuid.New(),
			AuthzAdmin:   "developer",
		}

		databaseRead.On("Find").Return(resp.SetData(repository))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.RepositoryMember,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.False(t, result)
		assert.Error(t, err)
	})

	t.Run("should return true and no error when successfully authenticate with repository supervisor", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"supervisor"}, nil)

		resp := response.Response{}
		repository := &accountEntities.Repository{
			RepositoryID:    uuid.New(),
			AuthzSupervisor: "supervisor",
		}

		databaseRead.On("Find").Return(resp.SetData(repository))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.RepositorySupervisor,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.True(t, result)
		assert.NoError(t, err)
	})

	t.Run("should return false and error when invalid ldap group with repository member", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"test"}, nil)

		resp := response.Response{}
		repository := &accountEntities.Repository{
			RepositoryID:    uuid.New(),
			AuthzSupervisor: "supervisor",
		}

		databaseRead.On("Find").Return(resp.SetData(repository))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.RepositorySupervisor,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.False(t, result)
		assert.Error(t, err)
	})

	t.Run("should return true and no error when successfully authenticate with repository admin", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"admin"}, nil)

		resp := response.Response{}
		repository := &accountEntities.Repository{
			RepositoryID: uuid.New(),
			AuthzAdmin:   "admin",
		}

		databaseRead.On("Find").Return(resp.SetData(repository))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.True(t, result)
		assert.NoError(t, err)
	})

	t.Run("should return false and error when invalid ldap group with repository member", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"test"}, nil)

		resp := response.Response{}
		repository := &accountEntities.Repository{
			RepositoryID:    uuid.New(),
			AuthzSupervisor: "admin",
		}

		databaseRead.On("Find").Return(resp.SetData(repository))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.False(t, result)
		assert.Error(t, err)
	})

	t.Run("should return error while getting company", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"test"}, nil)

		resp := response.Response{}
		databaseRead.On("Find").Return(resp.SetError(errors.New("test")))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.RepositoryAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.False(t, result)
		assert.Error(t, err)
	})

	t.Run("should return error while getting company", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"test"}, nil)

		resp := response.Response{}
		databaseRead.On("Find").Return(resp.SetError(errors.New("test")))
		databaseRead.On("SetFilter").Return(&gorm.DB{})

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         authEnums.CompanyAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.False(t, result)
		assert.Error(t, err)
	})

	t.Run("should return error when invalid token", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		credentials := auth.AuthorizationData{
			Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9" +
				"lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			Role:         authEnums.CompanyAdmin,
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.False(t, result)
		assert.Error(t, err)
	})

	t.Run("should return error when invalid role in authorization data", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		ldapClientServiceMock.On("GetGroupsOfUser").Return([]string{"test"}, nil)

		ldapService := &Service{
			client:         ldapClientServiceMock,
			accountRepo:    accountrepo.NewAccountRepository(databaseRead, databaseWrite),
			companyRepo:    companyrepo.NewCompanyRepository(databaseRead, databaseWrite),
			repositoryRepo: repositoryrepo.NewRepository(databaseRead, databaseWrite),
			cacheRepo:      cache.NewCacheRepository(databaseRead, databaseWrite),
		}

		token, _, _ := jwt.CreateToken(account, nil)

		credentials := auth.AuthorizationData{
			Token:        token,
			Role:         "test",
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		}

		result, err := ldapService.IsAuthorized(&credentials)

		assert.False(t, result)
		assert.Error(t, err)
	})
}
