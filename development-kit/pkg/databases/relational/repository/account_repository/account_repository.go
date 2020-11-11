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

package accountrepository

import (
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	"github.com/google/uuid"
)

type IAccountRepository interface {
	GetAccountRepository(accountID, repositoryID uuid.UUID) (*roles.AccountRepository, error)
	Create(accountRepository *roles.AccountRepository, transaction SQL.InterfaceWrite) error
	UpdateAccountRepository(accountRepository *roles.AccountRepository) error
	GetOfAccount(accountID uuid.UUID) (accountRepository []roles.AccountRepository, err error)
	DeleteAccountRepository(accountID, repositoryID uuid.UUID) error
	DeleteFromAllRepositories(accountID, companyID uuid.UUID) error
}

type AccountRepository struct {
	databaseRead  SQL.InterfaceRead
	databaseWrite SQL.InterfaceWrite
}

func NewAccountRepositoryRepository(
	databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) IAccountRepository {
	return &AccountRepository{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
	}
}

func (a *AccountRepository) GetAccountRepository(accountID, repositoryID uuid.UUID) (
	*roles.AccountRepository, error) {
	accountRepositoryRole := &roles.AccountRepository{}

	response := a.databaseRead.Find(
		&accountRepositoryRole,
		a.databaseRead.SetFilter(map[string]interface{}{"account_id": accountID, "repository_id": repositoryID}),
		accountRepositoryRole.GetTable(),
	)

	return accountRepositoryRole, response.GetError()
}

func (a *AccountRepository) Create(accountRepository *roles.AccountRepository, transaction SQL.InterfaceWrite) error {
	conn := a.databaseWrite
	if transaction != nil {
		conn = transaction
	}

	return conn.Create(accountRepository.SetCreateData(), accountRepository.GetTable()).GetError()
}

func (a *AccountRepository) UpdateAccountRepository(accountRepository *roles.AccountRepository) error {
	filter := map[string]interface{}{"account_id": accountRepository.AccountID,
		"repository_id": accountRepository.RepositoryID}

	toUpdate, err := a.GetAccountRepository(accountRepository.AccountID, accountRepository.RepositoryID)
	if err != nil {
		return err
	}

	return a.databaseWrite.Update(toUpdate.SetUpdateData(accountRepository.Role),
		filter, accountRepository.GetTable()).GetError()
}

func (a *AccountRepository) GetOfAccount(accountID uuid.UUID) (accountRepository []roles.AccountRepository, err error) {
	entity := &roles.AccountRepository{}

	response := a.databaseRead.Find(
		&accountRepository,
		a.databaseRead.SetFilter(map[string]interface{}{"account_id": accountID}),
		entity.GetTable(),
	)

	return accountRepository, response.GetError()
}

func (a *AccountRepository) DeleteAccountRepository(accountID, repositoryID uuid.UUID) error {
	return a.databaseWrite.Delete(map[string]interface{}{"account_id": accountID, "repository_id": repositoryID},
		"account_repository").GetError()
}

func (a *AccountRepository) DeleteFromAllRepositories(accountID, companyID uuid.UUID) error {
	return a.databaseWrite.Delete(map[string]interface{}{"account_id": accountID, "company_id": companyID},
		"account_repository").GetError()
}
