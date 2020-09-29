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

package repository

import (
	"fmt"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	"github.com/google/uuid"
)

type IRepository interface {
	Create(repository *accountEntities.Repository, transaction SQL.InterfaceWrite) error
	Update(repositoryID uuid.UUID, repository *accountEntities.Repository) (*accountEntities.Repository, error)
	Get(repositoryID uuid.UUID) (*accountEntities.Repository, error)
	List(accountID uuid.UUID, companyID uuid.UUID) (*[]accountEntities.RepositoryResponse, error)
	Delete(repositoryID uuid.UUID) error
	GetAllAccountsInRepository(repositoryID uuid.UUID) (*[]roles.AccountRole, error)
	GetByName(companyID uuid.UUID, repositoryName string) (*accountEntities.Repository, error)
}

type Repository struct {
	databaseWrite SQL.InterfaceWrite
	databaseRead  SQL.InterfaceRead
}

func NewRepository(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) IRepository {
	return &Repository{
		databaseWrite: databaseWrite,
		databaseRead:  databaseRead,
	}
}

func (r *Repository) Create(repository *accountEntities.Repository, transaction SQL.InterfaceWrite) error {
	conn := r.databaseWrite
	if transaction != nil {
		conn = transaction
	}

	return conn.Create(repository, repository.GetTable()).GetError()
}

func (r *Repository) Update(repositoryID uuid.UUID, repository *accountEntities.Repository) (
	*accountEntities.Repository, error) {
	toUpdate, err := r.Get(repositoryID)
	if err != nil {
		return nil, err
	}

	return repository, r.databaseWrite.Update(toUpdate.SetUpdateData(repository.Name,
		repository.Description), map[string]interface{}{"repository_id": repositoryID}, repository.GetTable()).GetError()
}

func (r *Repository) Get(repositoryID uuid.UUID) (*accountEntities.Repository, error) {
	repository := &accountEntities.Repository{}
	response := r.databaseRead.Find(repository,
		r.databaseRead.SetFilter(map[string]interface{}{"repository_id": repositoryID}), repository.GetTable())

	return repository, response.GetError()
}

func (r *Repository) List(accountID, companyID uuid.UUID) (*[]accountEntities.RepositoryResponse, error) {
	repositories := &[]accountEntities.RepositoryResponse{}

	query := r.databaseRead.
		GetConnection().
		Select("repo.repository_id, repo.company_id, repo.description, repo.name, accountRepo.role,"+
			" repo.created_at, repo.updated_at").
		Table("repositories AS repo").
		Joins("JOIN account_repository AS accountRepo ON accountRepo.repository_id = repo.repository_id"+
			" AND accountRepo.account_id = ?", accountID).
		Where("accountRepo.company_id = ? AND accountRepo.account_id = ?", companyID, accountID).
		Find(&repositories)

	return repositories, query.Error
}

func (r *Repository) Delete(repositoryID uuid.UUID) error {
	return r.databaseWrite.Delete(
		map[string]interface{}{"repository_id": repositoryID}, "repositories").GetError()
}

//nolint
func (r *Repository) GetAllAccountsInRepository(repositoryID uuid.UUID) (*[]roles.AccountRole, error) {
	accounts := &[]roles.AccountRole{}

	query := fmt.Sprintf(`SELECT
		"email", "username", "role", "accounts"."account_id"
		FROM "accounts"
		INNER JOIN "account_repository"
		ON "account_repository"."account_id" = "accounts"."account_id"
		WHERE ("account_repository"."repository_id" IN ('%s'))
	`, repositoryID)

	response := r.databaseRead.RawSQL(query, accounts)
	return accounts, response.GetError()
}

func (r *Repository) GetByName(companyID uuid.UUID, repositoryName string) (*accountEntities.Repository, error) {
	repository := &accountEntities.Repository{}
	response := r.databaseRead.Find(repository, r.databaseRead.SetFilter(
		map[string]interface{}{"company_id": companyID, "name": repositoryName}), repository.GetTable())

	return repository, response.GetError()
}
