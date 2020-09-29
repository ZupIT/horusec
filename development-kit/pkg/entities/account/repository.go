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
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	accountEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
)

type Repository struct {
	RepositoryID uuid.UUID `json:"repositoryID" gorm:"primary_key" swaggerignore:"true"`
	CompanyID    uuid.UUID `json:"companyID" swaggerignore:"true"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	CreatedAt    time.Time `json:"createdAt" swaggerignore:"true"`
	UpdatedAt    time.Time `json:"updatedAt" swaggerignore:"true"`
}

type RepositoryResponse struct {
	CompanyID    uuid.UUID        `json:"companyID"`
	RepositoryID uuid.UUID        `json:"repositoryID"`
	Name         string           `json:"name"`
	Role         accountEnum.Role `json:"role"`
	Description  string           `json:"description"`
	CreatedAt    time.Time        `json:"createdAt"`
	UpdatedAt    time.Time        `json:"updatedAt"`
}

func (r *Repository) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.CompanyID, validation.Required, is.UUID),
		validation.Field(&r.Name, validation.Required, validation.Length(1, 255)),
	)
}

func (r *Repository) SetCreateData(companyID uuid.UUID) *Repository {
	r.RepositoryID = uuid.New()
	r.CreatedAt = time.Now()
	r.UpdatedAt = time.Now()
	r.CompanyID = companyID
	return r
}

func (r *Repository) SetUpdateData(name, description string) *Repository {
	r.UpdatedAt = time.Now()
	r.Name = name
	r.Description = description
	return r
}

func (r *Repository) GetTable() string {
	return "repositories"
}

func (r *Repository) ToAccountRepository(role accountEnum.Role, accountID uuid.UUID) *roles.AccountRepository {
	accountRepository := &roles.AccountRepository{
		RepositoryID: r.RepositoryID,
		CompanyID:    r.CompanyID,
		AccountID:    accountID,
		Role:         role,
	}

	return accountRepository.SetCreateData()
}

func (r *Repository) ToRepositoryResponse(role accountEnum.Role) *RepositoryResponse {
	return &RepositoryResponse{
		RepositoryID: r.RepositoryID,
		CompanyID:    r.CompanyID,
		Name:         r.Name,
		Role:         role,
		Description:  r.Description,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}
