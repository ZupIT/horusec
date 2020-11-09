package account

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
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
		validation.Field(&c.AdminEmail, validation.Required, validation.Length(1, 255), is.Email),
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
