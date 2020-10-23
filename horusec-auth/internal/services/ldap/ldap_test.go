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
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	companyrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	repositoryrepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	ldapservice "github.com/ZupIT/horusec/development-kit/pkg/services/ldap"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
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
	t.Run("should retorn ldap auth response when authenticate is successfully and user exists", func(t *testing.T) {
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

	t.Run("should retorn ldap auth response when authenticate is successfully and user doesnt exist", func(t *testing.T) {
		databaseRead := &relational.MockRead{}
		databaseWrite := &relational.MockWrite{}
		ldapClientServiceMock := &ldapservice.Mock{}

		user := map[string]string{"username": "test", "email": "test@test.com"}
		ldapClientServiceMock.On("Authenticate").Return(true, user, nil)

		resp := response.Response{}
		databaseRead.On("Find").Return(resp.SetError(errors.New("")))
		databaseRead.On("SetFilter").Return(&gorm.DB{})
		databaseRead.On("Find").Return()
		databaseWrite.On("Create").Return(resp.SetData(user))

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
}
