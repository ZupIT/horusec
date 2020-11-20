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
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/google/uuid"
)

type IAccount interface {
	Create(account *authEntities.Account) error
	GetByAccountID(accountID uuid.UUID) (*authEntities.Account, error)
	GetByEmail(email string) (*authEntities.Account, error)
	Update(account *authEntities.Account) error
	GetByUsername(username string) (*authEntities.Account, error)
	DeleteAccount(accountID uuid.UUID) error
}

type Account struct {
	databaseRead  SQL.InterfaceRead
	databaseWrite SQL.InterfaceWrite
}

func NewAccountRepository(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) IAccount {
	return &Account{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
	}
}

func (a *Account) Create(account *authEntities.Account) error {
	return a.databaseWrite.Create(account, account.GetTable()).GetError()
}

func (a *Account) GetByAccountID(accountID uuid.UUID) (*authEntities.Account, error) {
	account := &authEntities.Account{}
	filter := a.databaseRead.SetFilter(map[string]interface{}{"account_id": accountID})
	result := a.databaseRead.Find(account, filter, account.GetTable())
	return account, result.GetError()
}

func (a *Account) GetByEmail(email string) (*authEntities.Account, error) {
	account := &authEntities.Account{}
	filter := a.databaseRead.SetFilter(map[string]interface{}{"email": email})
	result := a.databaseRead.Find(account, filter, account.GetTable())
	return account, result.GetError()
}

func (a *Account) Update(account *authEntities.Account) error {
	account.SetUpdatedAt()
	return a.databaseWrite.Update(account.ToUpdateMap(), map[string]interface{}{"account_id": account.AccountID},
		account.GetTable()).GetError()
}

func (a *Account) GetByUsername(username string) (*authEntities.Account, error) {
	account := &authEntities.Account{}
	filter := a.databaseRead.SetFilter(map[string]interface{}{"username": username})
	result := a.databaseRead.Find(account, filter, account.GetTable())
	return account, result.GetError()
}

func (a *Account) DeleteAccount(accountID uuid.UUID) error {
	return a.databaseWrite.Delete(map[string]interface{}{"account_id": accountID}, "accounts").GetError()
}
