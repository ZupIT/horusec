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
	"encoding/json"
	"time"

	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
)

type Company struct {
	CompanyID   uuid.UUID `json:"companyID" gorm:"primary_key" swaggerignore:"true"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	AuthzMember string    `json:"authzMember"`
	AuthzAdmin  string    `json:"authzAdmin"`
	CreatedAt   time.Time `json:"createdAt" swaggerignore:"true"`
	UpdatedAt   time.Time `json:"updatedAt" swaggerignore:"true"`
}

type CompanyResponse struct {
	CompanyID   uuid.UUID      `json:"companyID"`
	Name        string         `json:"name"`
	Role        rolesEnum.Role `json:"role"`
	Description string         `json:"description"`
	AuthzMember string         `json:"authzMember"`
	AuthzAdmin  string         `json:"authzAdmin"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
}

func (c *Company) Validate() error {
	return validation.ValidateStruct(c,
		validation.Field(&c.Name, validation.Required, validation.Length(1, 255)),
	)
}

func (c *Company) SetCreateData() *Company {
	c.CompanyID = uuid.New()
	c.CreatedAt = time.Now()
	c.UpdatedAt = time.Now()

	return c
}

func (c *Company) SetUpdateData() *Company {
	c.UpdatedAt = time.Now()
	return c
}

func (c *Company) MapToUpdate() map[string]interface{} {
	return map[string]interface{}{
		"name":         c.Name,
		"description":  c.Description,
		"authz_member": c.AuthzMember,
		"authz_admin":  c.AuthzAdmin,
		"updated_at":   c.UpdatedAt,
	}
}

func (c *Company) GetTable() string {
	return "companies"
}

func (c *Company) ToCompanyResponse(role rolesEnum.Role) *CompanyResponse {
	return &CompanyResponse{
		CompanyID:   c.CompanyID,
		Name:        c.Name,
		Role:        role,
		Description: c.Description,
		AuthzAdmin:  c.AuthzAdmin,
		AuthzMember: c.AuthzMember,
		CreatedAt:   c.CreatedAt,
		UpdatedAt:   c.UpdatedAt,
	}
}

func (c *Company) GetAuthzMember() string {
	return c.AuthzMember
}

func (c *Company) GetAuthzAdmin() string {
	return c.AuthzAdmin
}

func (c *Company) GetAuthzSupervisor() string {
	return ""
}

func (c *Company) ToBytes() []byte {
	bytes, _ := json.Marshal(c)
	return bytes
}
