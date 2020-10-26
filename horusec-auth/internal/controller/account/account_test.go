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
//
//import (
//	"github.com/Nerzal/gocloak/v7"
//	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
//	repositoryAccount "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
//	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
//	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
//	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
//	"github.com/ZupIT/horusec/development-kit/pkg/services/broker"
//	"github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
//	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"
//	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
//	"github.com/ZupIT/horusec/horusec-account/config/app"
//	"github.com/google/uuid"
//	"github.com/stretchr/testify/assert"
//	"testing"
//)
//
//func TestAccount_CreateAccountFromKeycloak(t *testing.T) {
//	t.Run("should success create account from keycloak", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		mockWrite.On("Create").Return(response.NewResponse(0, nil, nil))
//		cacheRepositoryMock := &cache.Mock{}
//		useCases := accountUseCases.NewAccountUseCases()
//		appConfig := app.SetupApp()
//		keycloakMock := &keycloak.Mock{}
//		email := "test@email.com"
//		sub := uuid.New().String()
//		name := uuid.New().String()
//		keycloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{
//			Email: &email,
//			Sub:   &sub,
//			Name:  &name,
//		}, nil)
//		controller := &Account{
//			useCases:              useCases,
//			broker:                brokerMock,
//			databaseWrite:         mockWrite,
//			databaseRead:          mockRead,
//			accountRepository:     repositoryAccount.NewAccountRepository(mockRead, mockWrite),
//			accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
//			cacheRepository:       cacheRepositoryMock,
//			appConfig:             appConfig,
//			keycloakService:       keycloakMock,
//		}
//		assert.NotNil(t, controller)
//
//		account := &accountEntities.KeycloakToken{
//			AccessToken: "some token",
//		}
//
//		err := controller.CreateAccountFromKeycloak(account)
//		assert.NoError(t, err)
//	})
//	t.Run("should return errror when email not exists in token", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		mockWrite.On("Create").Return(response.NewResponse(0, nil, nil))
//		cacheRepositoryMock := &cache.Mock{}
//		useCases := accountUseCases.NewAccountUseCases()
//		appConfig := app.SetupApp()
//		keycloakMock := &keycloak.Mock{}
//		name := uuid.New().String()
//		keycloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{
//			Name: &name,
//		}, nil)
//		controller := &Account{
//			useCases:              useCases,
//			broker:                brokerMock,
//			databaseWrite:         mockWrite,
//			databaseRead:          mockRead,
//			accountRepository:     repositoryAccount.NewAccountRepository(mockRead, mockWrite),
//			accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
//			cacheRepository:       cacheRepositoryMock,
//			appConfig:             appConfig,
//			keycloakService:       keycloakMock,
//		}
//		assert.NotNil(t, controller)
//
//		account := &accountEntities.KeycloakToken{
//			AccessToken: "some token",
//		}
//
//		err := controller.CreateAccountFromKeycloak(account)
//		assert.Error(t, err)
//	})
//	t.Run("Should return error when get user info", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		mockWrite.On("Create").Return(response.NewResponse(0, nil, nil))
//		cacheRepositoryMock := &cache.Mock{}
//		useCases := accountUseCases.NewAccountUseCases()
//		appConfig := app.SetupApp()
//		keycloakMock := &keycloak.Mock{}
//		keycloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{}, errors.New("some return error"))
//		controller := &Account{
//			useCases:              useCases,
//			broker:                brokerMock,
//			databaseWrite:         mockWrite,
//			databaseRead:          mockRead,
//			accountRepository:     repositoryAccount.NewAccountRepository(mockRead, mockWrite),
//			accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
//			cacheRepository:       cacheRepositoryMock,
//			appConfig:             appConfig,
//			keycloakService:       keycloakMock,
//		}
//		assert.NotNil(t, controller)
//
//		account := &accountEntities.KeycloakToken{
//			AccessToken: "some token",
//		}
//
//		err := controller.CreateAccountFromKeycloak(account)
//		assert.Error(t, err)
//	})
//	t.Run("should return error unique username key when create user from keycloak", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		mockWrite.On("Create").Return(response.NewResponse(0, errors.New("pq: duplicate key value violates unique constraint \"uk_accounts_username\""), nil))
//		cacheRepositoryMock := &cache.Mock{}
//		useCases := accountUseCases.NewAccountUseCases()
//		appConfig := app.SetupApp()
//		keycloakMock := &keycloak.Mock{}
//		email := "test@email.com"
//		sub := uuid.New().String()
//		name := uuid.New().String()
//		keycloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{
//			Email: &email,
//			Sub:   &sub,
//			Name:  &name,
//		}, nil)
//		controller := &Account{
//			useCases:              useCases,
//			broker:                brokerMock,
//			databaseWrite:         mockWrite,
//			databaseRead:          mockRead,
//			accountRepository:     repositoryAccount.NewAccountRepository(mockRead, mockWrite),
//			accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
//			cacheRepository:       cacheRepositoryMock,
//			appConfig:             appConfig,
//			keycloakService:       keycloakMock,
//		}
//		assert.NotNil(t, controller)
//
//		account := &accountEntities.KeycloakToken{
//			AccessToken: "some token",
//		}
//
//		err := controller.CreateAccountFromKeycloak(account)
//		assert.Error(t, err)
//	})
//	t.Run("should return error unique account key when create user from keycloak", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		mockWrite.On("Create").Return(response.NewResponse(0, errors.New("pq: duplicate key value violates unique constraint \"accounts_pkey\""), nil))
//		cacheRepositoryMock := &cache.Mock{}
//		useCases := accountUseCases.NewAccountUseCases()
//		appConfig := app.SetupApp()
//		keycloakMock := &keycloak.Mock{}
//		email := "test@email.com"
//		sub := uuid.New().String()
//		name := uuid.New().String()
//		keycloakMock.On("GetUserInfo").Return(&gocloak.UserInfo{
//			Email: &email,
//			Sub:   &sub,
//			Name:  &name,
//		}, nil)
//		controller := &Account{
//			useCases:              useCases,
//			broker:                brokerMock,
//			databaseWrite:         mockWrite,
//			databaseRead:          mockRead,
//			accountRepository:     repositoryAccount.NewAccountRepository(mockRead, mockWrite),
//			accountRepositoryRepo: repoAccountRepository.NewAccountRepositoryRepository(mockRead, mockWrite),
//			cacheRepository:       cacheRepositoryMock,
//			appConfig:             appConfig,
//			keycloakService:       keycloakMock,
//		}
//		assert.NotNil(t, controller)
//
//		account := &accountEntities.KeycloakToken{
//			AccessToken: "some token",
//		}
//
//		err := controller.CreateAccountFromKeycloak(account)
//		assert.Error(t, err)
//	})
//}
