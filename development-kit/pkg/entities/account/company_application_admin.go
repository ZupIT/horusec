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

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
)

type CompanyApplicationAdmin struct {
	CompanyID   uuid.UUID `json:"companyID" gorm:"primary_key" swaggerignore:"true"`
	Name        string    `json:"name"`
	AdminEmail  string    `json:"adminEmail"`
	Description string    `json:"description"`
	AuthzMember string    `json:"authzMember"`
	AuthzAdmin  string    `json:"authzAdmin"`
	CreatedAt   time.Time `json:"createdAt" swaggerignore:"true"`
	UpdatedAt   time.Time `json:"updatedAt" swaggerignore:"true"`
}

func (c *CompanyApplicationAdmin) Validate() error {
	return validation.ValidateStruct(c,
		validation.Field(&c.Name, validation.Required, validation.Length(1, 255)),
		validation.Field(&c.AdminEmail, validation.Required, validation.Length(1, 255)),
	)
}

func (c *CompanyApplicationAdmin) ToCompany() *Company {
	return &Company{
		CompanyID:   c.CompanyID,
		Name:        c.Name,
		Description: c.Description,
		AuthzAdmin:  c.AuthzAdmin,
		AuthzMember: c.AuthzMember,
		CreatedAt:   c.CreatedAt,
		UpdatedAt:   c.UpdatedAt,
	}
}
