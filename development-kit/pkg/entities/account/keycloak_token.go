package account

import (
	"encoding/json"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type KeycloakToken struct {
	AccessToken string `json:"accessToken"`
}

func (l *KeycloakToken) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.AccessToken, validation.Required),
	)
}

func (l *KeycloakToken) ToBytes() []byte {
	bytes, _ := json.Marshal(l)
	return bytes
}
