package account

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type ValidateUnique struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

func (v *ValidateUnique) Validate() error {
	return validation.ValidateStruct(v,
		validation.Field(&v.Email, validation.Required, validation.Length(1, 255), is.Email),
		validation.Field(&v.Username, validation.Length(1, 255), validation.Required),
	)
}
