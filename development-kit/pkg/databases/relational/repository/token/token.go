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

package token

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
)

type IRepository interface {
	Create(token *api.Token) (*api.Token, error)
	Delete(tokenID uuid.UUID) error
	GetByValue(value string) (*api.Token, error)
	GetAllOfRepository(repositoryID uuid.UUID) (*[]api.Token, error)
	GetAllOfCompany(CompanyID uuid.UUID) (*[]api.Token, error)
}

type Repository struct {
	databaseRead  relational.InterfaceRead
	databaseWrite relational.InterfaceWrite
}

func NewTokenRepository(databaseRead relational.InterfaceRead, databaseWrite relational.InterfaceWrite) IRepository {
	return &Repository{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
	}
}

func (t *Repository) Create(token *api.Token) (*api.Token, error) {
	r := t.databaseWrite.Create(token.SetCreateData(), token.GetTable())

	return t.parseTokenResponse(r)
}

func (t *Repository) Delete(tokenID uuid.UUID) error {
	e := &api.Token{}
	r := t.databaseWrite.Delete(map[string]interface{}{"token_id": tokenID}, e.GetTable())
	if r.GetError() != nil {
		return r.GetError()
	}
	if r.GetRowsAffected() == 0 {
		return EnumErrors.ErrNotFoundRecords
	}
	return nil
}

func (t *Repository) GetByValue(value string) (*api.Token, error) {
	token := &api.Token{}
	condition := t.databaseRead.SetFilter(map[string]interface{}{"value": value})
	r := t.databaseRead.Find(token, condition, token.GetTable())
	return t.parseTokenResponse(r)
}

func (t *Repository) GetAllOfRepository(repositoryID uuid.UUID) (*[]api.Token, error) {
	table := api.Token{}
	query := t.databaseRead.SetFilter(map[string]interface{}{"repository_id": repositoryID})
	r := t.databaseRead.Find(&[]api.Token{}, query, table.TableName())
	return t.parseResponseToTokenArray(r)
}

func (t *Repository) GetAllOfCompany(companyID uuid.UUID) (*[]api.Token, error) {
	table := api.Token{}
	query := t.databaseRead.SetFilter(map[string]interface{}{"company_id": companyID, "repository_id": nil})
	r := t.databaseRead.Find(&[]api.Token{}, query, table.TableName())
	return t.parseResponseToTokenArray(r)
}

func (t *Repository) parseResponseToTokenArray(result *response.Response) (*[]api.Token, error) {
	if result.GetError() != nil || result.GetData() == nil {
		return nil, result.GetError()
	}

	return result.GetData().(*[]api.Token), nil
}

func (t *Repository) parseTokenResponse(r *response.Response) (*api.Token, error) {
	if r.GetData() == nil {
		return nil, r.GetError()
	}

	return r.GetData().(*api.Token), r.GetError()
}
