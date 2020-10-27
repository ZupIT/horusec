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
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAccount "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/keycloak"
	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"
)

type IAccount interface {
	CreateAccountFromKeycloak(keyCloakToken *accountEntities.KeycloakToken) error
}

type Account struct {
	useCases          accountUseCases.IAccount
	accountRepository repositoryAccount.IAccount
	keycloakService   keycloak.IService
}

func NewAccountController(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite,
	useCases accountUseCases.IAccount) IAccount {
	return &Account{
		useCases:          useCases,
		accountRepository: repositoryAccount.NewAccountRepository(databaseRead, databaseWrite),
		keycloakService:   keycloak.NewKeycloakService()}
}

func (a *Account) CreateAccountFromKeycloak(keyCloakToken *accountEntities.KeycloakToken) error {
	account, err := a.newAccountFromKeycloakToken(keyCloakToken.AccessToken)
	if err != nil {
		return err
	}

	if err := a.accountRepository.Create(account); err != nil {
		return a.useCases.CheckCreateAccountErrorType(err)
	}

	return nil
}

func (a *Account) newAccountFromKeycloakToken(accessToken string) (*accountEntities.Account, error) {
	userInfo, err := a.keycloakService.GetUserInfo(accessToken)
	if err != nil {
		return nil, err
	}
	if userInfo.Email == nil || userInfo.Sub == nil {
		return nil, errors.ErrorInvalidKeycloakToken
	}
	if userInfo.PreferredUsername == nil {
		userInfo.PreferredUsername = userInfo.Name
	}
	return a.useCases.NewAccountFromKeyCloakUserInfo(userInfo), nil
}
