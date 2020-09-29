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
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/google/uuid"
)

type IAccount interface {
	Create(account *accountEntities.Account) error
	GetByAccountID(accountID uuid.UUID) (*accountEntities.Account, error)
	GetByEmail(email string) (*accountEntities.Account, error)
	Update(account *accountEntities.Account) error
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

func (a *Account) Create(account *accountEntities.Account) error {
	return a.databaseWrite.Create(account, account.GetTable()).GetError()
}

func (a *Account) GetByAccountID(accountID uuid.UUID) (*accountEntities.Account, error) {
	account := &accountEntities.Account{}
	filter := a.databaseRead.SetFilter(map[string]interface{}{"account_id": accountID})
	result := a.databaseRead.Find(account, filter, account.GetTable())
	return account, result.GetError()
}

func (a *Account) GetByEmail(email string) (*accountEntities.Account, error) {
	account := &accountEntities.Account{}
	filter := a.databaseRead.SetFilter(map[string]interface{}{"email": email})
	result := a.databaseRead.Find(account, filter, account.GetTable())
	return account, result.GetError()
}

func (a *Account) Update(account *accountEntities.Account) error {
	account.SetUpdatedAt()
	return a.databaseWrite.Update(account.ToMap(), map[string]interface{}{"account_id": account.AccountID},
		account.GetTable()).GetError()
}
